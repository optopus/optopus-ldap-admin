require 'optopus/plugin'
require 'net/ldap'
require_relative 'lib/ldap_admin'

module Optopus
  module Plugin
    module LdapAdmin
      extend Optopus::Plugin
      plugin do
        ldap_menu = Optopus::Menu::Section.new(:name => 'ldap_menu', :required_role => ['admin', 'ldap_admin'])
        ldap_menu.add_link :display => 'LDAP Admin', :href => '/ldap'
        register_utility_menu ldap_menu
        register_role 'ldap_admin'
      end

      helpers do
        def ldap_admin
          return @ldap_admin if @ldap_admin
          plugin_settings = settings.plugins['ldap_admin']
          ldap_settings = {
            :base_dn    => plugin_settings['base_dn'],
            :host       => plugin_settings['host'],
            :port       => plugin_settings['port'] || 389,
            :encryption => :start_tls,
            :auth       => {
              :method   => :simple,
              :username => plugin_settings['bind_dn'],
              :password => plugin_settings['bind_password'],
            }
          }
          @ldap_admin = LDAPAdmin.new(ldap_settings)
        end

        def posixaccounts
          ldap_admin.posixaccounts
        end

        def posixaccount_from_params
          results = ldap_admin.lookup_username(params[:username])
          raise 'Invalid posixaccount' unless results
          @posixaccount = LDAPAdmin::PosixAccount.new(results)
        end

        def group_from_dn(group_dn)
          if group_dn.match(/^cn=(\w+),/)
            $1
          end
        end
      end

      get '/ldap', :auth => [:ldap_admin, :admin] do
        erb :admin_ldap
      end

      get '/ldap/:username/changepassword', :auth => [:ldap_admin, :admin] do
        posixaccount_from_params
        erb :admin_ldap_change_password
      end

      post '/ldap/:username/changepassword', :auth => [:ldap_admin, :admin] do
        begin
          validate_param_presence 'account-password'
          posixaccount_from_params
          hash = ldap_admin.password_hash(params['account-password'])
          ldap_admin.update_posixaccount_password(@posixaccount.uid, hash)
          flash[:success] = "Successfully changed #{@posixaccount.uid}'s password!"
          register_event "{{ references.user.to_link }} changed password for #{@posixaccount.uid} in ldap", :type => 'ldap_changepassword'
          redirect back
        rescue Exception => e
          handle_error(e)
        end
      end

      get '/ldap/posixaccount/:username/delete', :auth => [:ldap_admin, :admin] do
        results = ldap_admin.lookup_username(params[:username])
        raise 'Invalid posixaccount' unless results
        @posixaccount = LDAPAdmin::PosixAccount.new(results)
        erb :admin_ldap_delete_account
      end

      delete '/ldap/posixaccount/:username', :auth => [:ldap_admin, :admin] do
        ldap_admin.delete_posixaccount(params[:username])
        flash[:success] = "Successfully deleted ldap account '#{params[:username]}'"
        register_event "{{ references.user.to_link }} deleted '#{params[:username]}' from ldap", :type => 'ldap_delete'
        redirect '/ldap'
      end

      # Disabling users
      get '/ldap/posixaccount/:username/disable', :auth => [:ldap_admin, :admin] do
        results = ldap_admin.lookup_username(params[:username])
        raise 'Invalid posixaccount' unless results
        @posixaccount = LDAPAdmin::PosixAccount.new(results)
        erb :admin_ldap_disable_account
      end

      post '/ldap/posixaccount/:username/disable', :auth => [:ldap_admin, :admin] do
        begin
          hash = ldap_admin.password_hash(ldap_admin.random_password)
          ldap_admin.update_posixaccount_password(@posixaccount.uid, hash)
          ldap_admin.update_posixaccount_loginshell(@posixaccount.uid, '/sbin/nologin')
          flash[:success] = "Successfully disabled ldap account '#{params[:username]}'"
        rescue Exception => e
          handle_error(e)
        end
      end

      post '/ldap/posixaccount/:username/groups', :auth => [:ldap_admin, :admin] do
        begin
          results = ldap_admin.lookup_username(params[:username])
          raise 'Invalid posixaccount' unless results
          account = LDAPAdmin::PosixAccount.new(results)
          new_group_dns = params.keys.select { |k| k.match(/^group_/) }.map { |k| params[k] }
          old_group_dns = ldap_admin.lookup_memberuid(account.uid).map { |e| LDAPAdmin::PosixGroup.new(e).dn }
          new_group_dns.sort!
          old_group_dns.sort!
          unless new_group_dns == old_group_dns
            # remove any group DN that exists in the old/new array
            intersection = new_group_dns & old_group_dns
            new_group_dns -= intersection
            old_group_dns -= intersection

            # anything left in old needs to be removed
            old_group_dns.each do |group_dn|
              ldap_admin.delete_memberuid_from_group(group_dn, account.uid)
              group_name = group_from_dn(group_dn)
              register_event "{{ references.user.to_link }} removed '#{account.uid}' from group '#{group_name}'", :type => 'ldap_delete'
            end

            # anything left in new needs to be added
            new_group_dns.each do |group_dn|
              ldap_admin.add_memberuid_to_group(group_dn, account.uid)
              group_name = group_from_dn(group_dn)
              register_event "{{ references.user.to_link }} added '#{account.uid}' to group '#{group_name}'", :type => 'ldap_add'
            end
          end
          flash[:success] = "Successfully modified #{account.uid}'s group membership!"
        rescue Exception => e
          handle_error(e)
        end

        redirect back
      end

      get '/ldap/posixaccount/:username/groups', :auth => [:ldap_admin, :admin] do
        begin
          results = ldap_admin.lookup_username(params[:username])
          raise 'Invalid posixaccount' unless results
          @posixaccount = LDAPAdmin::PosixAccount.new(results)
          ldap_admin.lookup_memberuid(@posixaccount.uid).each do |entry|
            @posixaccount.groups << LDAPAdmin::PosixGroup.new(entry)
          end
          erb :admin_ldap_account
        rescue Exception => e
          handle_error(e)
        end
      end

      get '/ldap/createaccount', :auth => [:ldap_admin, :admin] do
        erb :admin_ldap_create_account
      end

      put '/ldap/createaccount', :auth => [:ldap_admin, :admin] do
        begin
          validate_param_presence 'account-fullname', 'account-password', 'account-username', 'account-primary-group'
          password_hash = ldap_admin.password_hash(params['account-password'])
          name_parts = params['account-fullname'].split(' ')
          first = name_parts.first
          last = name_parts.last
          ldap_admin.create_posixaccount(params['account-username'], password_hash,
                                         first, last, params['account-primary-group'])
          register_event "{{ references.user.to_link }} created '#{params['account-username']}' in ldap", :type => 'ldap_createaccount'
          flash[:success] = "Successfully created account for '#{params['account-username']}'"
        rescue Exception => e
          handle_error(e)
        end
        redirect back
      end


      def self.registered(app)
        raise 'Missing LDAP Admin plugin configuration' unless app.settings.respond_to?(:plugins) && app.settings.plugins.include?('ldap_admin')
        plugin_settings = app.settings.plugins['ldap_admin']
        raise 'Missing LDAP bind dn' unless plugin_settings.include?('bind_dn')
        raise 'Missing LDAP bind password' unless plugin_settings.include?('bind_password')
        raise 'Missing LDAP host' unless plugin_settings.include?('host')
        raise 'Missing LDAP base dn' unless plugin_settings.include?('base_dn')
        super(app)
      end
    end
  end
end
