require 'optopus/plugin'
require 'net/ldap'
require_relative 'lib/ldap_admin'

module Optopus
  module Plugin
    module LdapAdmin
      extend Optopus::Plugin
      plugin do
        ldap_menu = Optopus::Menu::Section.new(:name => 'ldap_menu', :required_role => 'admin')
        ldap_menu.add_link :display => 'LDAP Admin', :href => '/admin/ldap'
        register_utility_menu ldap_menu
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
      end

      get '/admin/ldap' do
        erb :admin_ldap
      end

      get '/admin/ldap/createaccount' do
        erb :admin_ldap_create_account
      end

      put '/admin/ldap/createaccount' do
        begin
          validate_param_presence 'account-fullname', 'account-password', 'account-username', 'account-primary-group'
          password_hash = ldap_admin.password_hash(params['account-password'])
          name_parts = params['account-fullname'].split(' ')
          first = name_parts.first
          last = name_parts.last
          ldap_admin.create_posixaccount(params['account-username'], password_hash,
                                         first, last, params['account-primary-group'])
        rescue Exception => e
          handle_error(e)
        end
        redirect back
      end

      get '/admin/ldap/posixaccount/:username/delete' do
          results = ldap_admin.lookup_username(params[:username])
          raise 'Invalid posixaccount' unless results
          @posixaccount = LDAPAdmin::PosixAccount.new(results)
          erb :admin_ldap_delete_account
      end

      delete '/admin/ldap/posixaccount/:username' do
        ldap_admin.delete_posixaccount(params[:username])
        redirect '/admin/ldap'
      end

      post '/admin/ldap/posixaccount/:username/groups' do
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
            end

            # anything left in new needs to be added
            new_group_dns.each do |group_dn|
              ldap_admin.add_memberuid_to_group(group_dn, account.uid)
            end
          end
        rescue Exception => e
          handle_error(e)
        end

        redirect back
      end

      get '/admin/ldap/posixaccount/:username/groups' do
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
