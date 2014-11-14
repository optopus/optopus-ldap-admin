require 'optopus/plugin'
require 'net/ldap'
require 'net/smtp'
require 'csv'
require 'time'
require_relative 'lib/ldap_admin'

module Optopus
  module Plugin
    module LdapAdmin
      extend Optopus::Plugin

      module UserUtils
        # Allow a user DN to be overridden in the properties column
        def ldap_dn
          self.properties['ldap_dn'] || LDAPAdmin.instance.dn_from_username(ldap_uid)
        end

        # Allow a user UID to be overridden in the properties column
        def ldap_uid
          self.properties['ldap_uid'] || self.username
        end

        # Return a valid posixaccount object for this optopus user
        def ldap_posixaccount
          if entry = LDAPAdmin.instance.lookup_username(ldap_uid)
            LDAPAdmin::PosixAccount.new(entry)
          end
        end
      end

      plugin do
        ldap_menu = Optopus::Menu::Section.new(:name => 'ldap_menu', :required_role => ['admin', 'ldap_admin'])
        ldap_menu.add_link :display => 'LDAP Admin', :href => '/ldap'
        register_utility_menu ldap_menu
        register_role 'ldap_admin'
        register_mixin :users, Optopus::Plugin::LdapAdmin::UserUtils
        register_partial :user_profile, :user_ldap_info, :display => 'LDAP Data'

        profile_password_menu = Optopus::Menu::Section.new(:name => 'ldap_password_menu')
        profile_password_menu.add_link :display => '<i class="icon icon-lock"></i> Change LDAP password', :href => '/ldap/user_change_password'
        register_profile_menu profile_password_menu

        if plugin_settings['ssh_key_management']
          profile_ssh_key_menu = Optopus::Menu::Section.new(:name => 'ldap_key_menu')
          profile_ssh_key_menu.add_link :display => '<i class="icon icon-lock"></i> Manage LDAP ssh keys', :href => '/ldap/manage_ssh_keys'
          register_profile_menu profile_ssh_key_menu
        end
      end

      helpers do
        def ldap_admin
          LDAPAdmin.instance
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

        def ssh_key_managment_enabled
          settings.plugins['ldap_admin'].include?('ssh_key_management') && settings.plugins['ldap_admin']['ssh_key_management'] == true
        end
      end

      get '/ldap', :auth => [:ldap_admin, :admin] do
        erb :admin_ldap
      end

      get '/ldap/report', :auth => [:ldap_admin, :admin] do
        # Let users get a dump of everything in our LDAP tree
        begin
          # Generate our CSV file in memory
          csv_data = CSV.generate do |csv|
            csv << ["# CN", "UID", "UID Number", "DN", "GID Number", "Home Directory", "Login Shell", "Groups"]
            posixaccounts.each do |account|
              account_groups = []
              account.groups.each do |group|
                account_groups.push(group.cn)
              end
              csv << [account.cn, account.uid, account.uidnumber, account.dn, "#{account.gidnumber} (#{account.posixgroup.cn})", account.homedirectory, account.loginshell, "#{account_groups.join(' / ')}"]
            end
          end

          # Download the file and send us back.
          content_type 'application/csv'
          attachment "optopus_ldap_report_#{Time.now.to_i}.csv"
          return csv_data

        rescue Exception => e
          handle_error(e)
        end
      end

      get '/ldap/:username/changepassword', :auth => [:ldap_admin, :admin] do
        posixaccount_from_params
        erb :admin_ldap_change_password
      end

      get '/ldap/posixaccount/:username/managesshkeys', :auth => [:ldap_admin, :admin] do
        begin
          if !ssh_key_managment_enabled
            raise "Your LDAP plugin is not currently setup for SSH key management"
          end
          posixaccount_from_params
          erb :admin_manage_ssh_keys
        rescue Exception => e
          handle_error(e)
        end
      end

      post '/ldap/posixaccount/:username/deletesshkey/:index/', :auth => [:ldap_admin, :admin] do
        begin
          if !ssh_key_managment_enabled
            raise "Your LDAP plugin is not currently setup for SSH key management"
          end
          ldap_admin.delete_ssh_key(params[:username],params[:index])
          flash[:success] = "Successfully deleted an SSH key to #{params[:username]}'s account"
          register_event "{{ references.user.to_link }} deleted an ssh key for #{params[:username]} in ldap", :type => 'ldap_deletesshkey'
          redirect back
        rescue Exception => e
          handle_error(e)
        end
      end

      post '/ldap/posixaccount/:username/add_ssh_key/', :auth => [:ldap_admin, :admin] do
        begin
          if !ssh_key_managment_enabled
            raise "Your LDAP plugin is not currently setup for SSH key management"
          end
          validate_param_presence 'sshkey'
          ldap_admin.add_ssh_key(params[:username],params[:sshkey])
          flash[:success] = "Successfully added an SSH key to #{params[:username]}'s account"
          register_event "{{ references.user.to_link }} added an ssh key for #{params[:username]} in ldap", :type => 'ldap_addsshkey'
          redirect back
        rescue Exception => e
          handle_error(e)
        end
      end

      post '/ldap/:username/changepassword', :auth => [:ldap_admin, :admin] do
        begin
          validate_param_presence 'account-password'
          posixaccount_from_params
          validation_info = ldap_admin.validate_password(params['account-password'], params[:username])
          if validation_info[:password_is_valid]
            hash = ldap_admin.password_hash(params['account-password'])
            ldap_admin.update_posixaccount_password(@posixaccount.uid, hash)
            flash[:success] = "Successfully changed #{@posixaccount.uid}'s password!"
            register_event "{{ references.user.to_link }} changed password for #{@posixaccount.uid} in ldap", :type => 'ldap_changepassword'
          else
            flash[:error] = "Failed to change #{@posixaccount.uid}'s password: #{validation_info[:error_message]}"
          end
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
          ldap_admin.update_posixaccount_password(params[:username], hash)
          ldap_admin.delete_all_ssh_keys(params[:username])
          ldap_admin.update_posixaccount_loginshell(params[:username], '/sbin/nologin')
          flash[:success] = "Successfully disabled ldap account '#{params[:username]}'"
          register_event "{{ references.user.to_link }} disabled '#{params[:username]}' from ldap", :type => 'ldap_disabl'
          redirect '/ldap'
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

      get '/ldap/manage_ssh_keys' do
        erb :user_manage_ssh_keys
      end

      delete '/ldap/manage_ssh_keys' do
        begin
          validate_param_presence 'delete-ldap-password', 'key-index'
          if @user.ldap_posixaccount.valid_password?(params['delete-ldap-password'])
            ldap_admin.delete_ssh_key(@user.username, params['key-index'])
            flash[:success] = "Successfully removed an ssh key!"
          else
            raise "Invalid LDAP pasword!"
          end
        rescue Exception => e
          handle_error(e)
        end
        redirect back
      end

      put '/ldap/manage_ssh_keys' do
        begin
          validate_param_presence 'add-ldap-password', 'key-content'
          if @user.ldap_posixaccount.valid_password?(params['add-ldap-password'])
            key = params['key-content'].strip
            ldap_admin.add_ssh_key(@user.username, key)
            flash[:success] = "Successfully added an ssh key!"
          else
            raise "Invalid LDAP pasword!"
          end
        rescue Exception => e
          handle_error(e)
        end
        redirect back
      end

      # Let users change their own passwords
      get '/ldap/user_change_password' do
        erb :user_change_password
      end

      post '/ldap/user_change_password' do
        begin
          validate_param_presence 'account-password', 'verify-account-password'
          validation_info = ldap_admin.validate_password(params['account-password'], @user.username)
          if validation_info[:password_is_valid]
            hash = ldap_admin.password_hash(params['account-password'])
            ldap_admin.update_posixaccount_password(@user.ldap_posixaccount.uid, hash)
            flash[:success] = "Your LDAP password has been successfully changed."
          else
            flash[:error] = "Failed to change your password; #{validation_info[:error_message]}"
          end
          redirect back
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
        LDAPAdmin.instance.update_settings(ldap_settings)
        super(app)
      end
    end
  end
end
