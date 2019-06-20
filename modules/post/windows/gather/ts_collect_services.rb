require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'


class MetasploitModule < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Services



  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Collect Windows services and basic information on each.',
      'Description'   => %q{
        Collect Windows services and basic information on each.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos.perez[at]trustedsec.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    results_table = Rex::Text::Table.new(
        'Header'     => 'Services',
        'Indent'     => 1,
        'SortIndex'  => 0,
        'Columns'    => ['Name', 'DisplayName', 'Status',]
    )

    service_list.each do |srv|
      if srv[:status] == 4
        results_table << [srv[:name],srv[:display], "Running"]
      end
    end

    print_line(results_table.to_s)
    report_note(
      :host   => session.session_host,
      :type   => 'host.info.services',
      :data   => {
        :services => results_table.to_csv},
      :update => :unique)

  end

end