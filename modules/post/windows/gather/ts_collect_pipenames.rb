require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'msf/core/post/windows/extapi'
require 'sqlite3'

class MetasploitModule < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::File


  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Collect the names on existing named pipes.',
      'Description'   => %q{
        Collect the names on existing named pipes.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos.perez[at]trustedsec.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    pipe_names = []
    session.fs.dir.foreach('\\\\.\\pipe\\\\') do |pipe|
        print_good("\t#{pipe}")
        pipe_names << pipe
    end
    report_note(
              :host   => session,
              :type   => 'host.info.pipes',
              :data   => {
                :names => pipe_names},
              :update => :unique)
  end

end