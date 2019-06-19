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


end