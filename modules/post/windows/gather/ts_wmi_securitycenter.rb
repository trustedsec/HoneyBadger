##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
      'Name'          => 'Collect AV, Firewall and AntiMalware settings via WMI.',
      'Description'   => %q{
        Collect AV, Firewall and AntiMalware settings via WMI.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos.perez[at]trustedsec.com>'  ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    get_sec_product2
  end

  def get_sec_product2()
    extapi_loaded = load_extapi
    if !extapi_loaded
        print_error "ExtAPI failed to load"
        return
    end
    queries = []
    
    queries << {
      :query => "SELECT displayName,pathToSignedProductExe,productState FROM AntiVirusProduct",
      :product => 'AntiVirus'}
    queries << {
      :query => "SELECT displayName,pathToSignedProductExe,productState FROM AntiSpywareProduct",
      :product => 'AntiSpyware'}
    queries << {
      :query => "SELECT displayName,pathToSignedProductExe,productState FROM FirewallProduct",
      :product => 'Firewall'}

    queries.each do |q|
        begin
            objects = session.extapi.wmi.query(q[:query],'root\securitycenter2')
            print_status("Enumerating registed #{q[:product]}")
            if objects
              objects[:values].each do |o|
                print_good("\tName: #{o[0]}")
                print_good("\tPath: #{o[1]}")
                status_bit = o[2].to_i.to_s(16).slice(1,1)
                if status_bit == '1'
                  status = 'Enabled'
                elsif status_bit == '0'
                  status = 'Disabled'
                else
                  status = 'Unknown'
                end
                print_good("\tStatus: #{status}")
                print_good(" ")
              end
            end
         rescue RuntimeError
           print_error "A runtime error was encountered when querying for #{q[:product]}"
        end
    end
    end
end