require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows check for commandline logging',
      'Description'   => %q{
        Windows check for commandline logging.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlo.perez[at]trustedsec.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module  #{sysinfo['Computer']} in session #{datastore['SESSION']}")
    settings = get_settings
    settings.each do |s|
      print_status(s)
    end
  end

  def get_settings()
    settings_vals = registry_enumvals('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit')
    return settings_vals
  end

  
end