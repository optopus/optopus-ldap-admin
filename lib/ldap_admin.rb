require_relative 'password'

class LDAPAdminError < StandardError; end
class LDAPAdmin
  class PosixAccount
    attr_reader :entry, :dn, :cn, :uid, :uidnumber, :gidnumber, :homedirectory, :loginshell
    attr_accessor :posixgroup, :groups
    def initialize(entry)
      @dn = entry.dn.first
      @entry = entry
      @cn = entry.cn.first
      @uid = entry.uid.first
      @uidnumber = entry.uidnumber.first
      @gidnumber = entry.gidnumber.first
      @homedirectory = entry.homedirectory.first
      @loginshell = entry.loginshell.first
      @groups = []
    end

    def member_of?(group_dn)
      @groups.each do |group|
        return true if group.dn == group_dn
      end
      false
    end
  end

  class PosixGroup
    attr_reader :entry, :cn, :gidnumber, :dn, :memberuid
    def initialize(entry)
      @entry = entry
      @cn = entry[:cn].first
      @gidnumber = entry[:gidnumber].first
      @dn = entry[:dn].first
      @memberuid = entry[:memberuid].first
    end

    def to_s
      self.cn
    end
  end

  attr_accessor :base_dn, :people_dn, :group_dn
  def initialize(settings={})
    @base_dn = settings.delete(:base_dn)
    @people_dn = settings.delete(:people_dn) || "ou=People,#{@base_dn}"
    @group_dn = settings.delete(:group_dn) || "ou=Groups,#{@base_dn}"
    @net_ldap = Net::LDAP.new(settings)
  end

  def posixaccounts
    results = Array.new
    @net_ldap.open do |ldap|
      ldap.search(:base => @base_dn, :filter => '(objectclass=posixaccount)') do |entry|
        results << PosixAccount.new(entry)
      end
    end
    results.each do |account|
      posixgroup = lookup_gidnumber(account.gidnumber)
      unless posixgroup.nil?
        account.posixgroup = PosixGroup.new(posixgroup)
      end
    end
    results
  end

  def posixgroups
    results = Array.new
    @net_ldap.open do |ldap|
      ldap.search(:base => @base_dn, :filter => '(objectclass=posixgroup)') do |entry|
        results << PosixGroup.new(entry)
      end
    end
    results
  end

  def next_uidnumber
    uids = posixaccounts.map { |e| e.uidnumber }.sort
    uids.last.to_i + 1
  end

  def random_password
    SecureRandom.base64
  end

  def password_hash(string)
    Net::LDAP::Password.generate(:ssha, string)
  end

  def lookup_memberuid(uid)
    search_settings = {
      :base   => @group_dn,
      :filter => "(&(objectclass=posixgroup)(memberuid=#{uid}))",
    }
    results = nil
    @net_ldap.open do |ldap|
      results = ldap.search(search_settings)
    end
    results
  end

  def lookup_gidnumber(gidnumber)
    gidnumber = gidnumber.to_i
    @gid_cache ||= Hash.new
    if @gid_cache[gidnumber]
      return @gid_cache[gidnumber]
    else
      search_settings = {
        :base   => @group_dn,
        :filter => "(&(objectclass=posixgroup)(gidnumber=#{gidnumber}))",
      }
      @net_ldap.open do |ldap|
        @gid_cache[gidnumber] = ldap.search(search_settings)
      end

      if @gid_cache[gidnumber].size > 1
        raise LDAPAdminError, "Multiple entries exist for gidNumber '#{gidnumber}'"
      end

      @gid_cache[gidnumber] = @gid_cache[gidnumber].first
    end
  end

  def lookup_username(username)
    @uid_cache ||= Hash.new
    if @uid_cache[username]
      return @uid_cache[username]
    else
      search_settings = {
        :base   => @people_dn,
        :filter => "(&(objectclass=posixaccount)(uid=#{username}))",
      }
      @net_ldap.open do |ldap|
        @uid_cache[username] = ldap.search(search_settings)
      end

      if @uid_cache[username].size > 1
        raise LDAPAdminError, "Multiple entries exist for uid '#{username}'"
      end

      @uid_cache[username] = @uid_cache[username].first
    end
  end

  def create_posixaccount(username, password_hash, first_name, last_name, gidnumber, shell='/bin/bash')
    uidnumber = next_uidnumber
    dn = dn_from_username(username)
    attrs = {
      :cn            => "#{first_name} #{last_name}",
      :objectclass   => ['posixAccount', 'inetOrgPerson'],
      :sn            => last_name,
      :uid           => username,
      :gecos         => first_name,
      :gidNumber     => gidnumber.to_s,
      :uidNumber     => uidnumber.to_s,
      :homeDirectory => "/home/#{username}",
      :loginShell    => shell,
      :userPassword  => password_hash,
    }

    @net_ldap.open do |ldap|
      if ldap.add(:dn => dn, :attributes => attrs) == false
        raise LDAPAdminError, "Operation Failed: #{ldap.get_operation_result.message}"
      end
    end

    # also add this user to a group that belongs to the gidnumber
    group = PosixGroup.new(lookup_gidnumber(gidnumber.to_s))
    add_memberuid_to_group(group.dn, username)
  end

  def delete_posixaccount(username)
    dn = dn_from_username(username)
    @net_ldap.open do |ldap|
      ldap.delete(:dn => dn)
    end

    # Also need to go through and delete all group membership
    lookup_memberuid(username).map { |e| LDAPAdmin::PosixGroup.new(e).dn }.each do |group_dn|
      delete_memberuid_from_group(group_dn, username)
    end
  end

  def update_posixaccount_password(username, password_hash)
    ops = [ [:replace, :userPassword, password_hash] ]
    dn = dn_from_username(username)
    @net_ldap.open do |ldap|
      ldap.modify(:dn => dn, :operations => ops)
    end
  end

  def delete_memberuid_from_group(group_dn, memberuid)
    ops = [ [:delete, :memberuid, memberuid] ]
    @net_ldap.open do |ldap|
      ldap.modify(:dn => group_dn, :operations => ops)
    end
  end

  def add_memberuid_to_group(group_dn, memberuid)
    ops = [ [:add, :memberuid, memberuid] ]
    @net_ldap.open do |ldap|
      ldap.modify(:dn => group_dn, :operations => ops)
    end
  end

  def dn_from_username(username)
    "uid=#{username},#{@people_dn}"
  end
end
