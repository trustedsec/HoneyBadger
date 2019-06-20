##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'msf/core/post/windows/extapi'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::ExtAPI

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather PowerCycle Times',
      'Description'   => %q{
        Get the last couple of startup and shutdown events so as to get a pattern of power cycles to determine
        best action for a persistence strategy.
      },
      'License'       => BSD_LICENSE ,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
    register_options(
      [
        OptInt.new('MAX_SEARCH', [false, 'Maximum number of hours before current day to pull.', 5])
      ]
    )
  end

  def run
    print_status("Getting Power Cycle times for #{sysinfo['Computer']} from the Event Log.")
    extapi_loaded = load_extapi
    if extapi_loaded
        # Using no offset for GMT time.
        time = DateTime.now.advance(:days => -(datastore['MAX_SEARCH']))
        wmi_time = time.strftime("%Y%m%d%H%M%S.000000-000")

        print_status('Restart, Shutdown and Boot up:')
        query_power_events(wmi_time)
        

    else
      print_error "ExtAPI failed to load"
    end

  end

  def query_power_events(wmi_time)
    tbl = Rex::Text::Table.new(
          'Columns' => [
            'Action',
            'Time',
            'Reason',
            'Type'
          ],
          'SortIndex'=> -1)
    query = "Select EventCode,TimeGenerated,InsertionStrings From Win32_NTLogEvent Where TimeWritten >= '#{wmi_time}' And Logfile = 'System' And (EventCode = '6009' OR EventCode = '1074')"
    objects = session.extapi.wmi.query(query)
    objects[:values].each do |event|
        
        if event[0]== "6009"
            action = "Start"
            tbl << [action, event[2], nil, nil]
        else
            action = "Stop"
            message_insertions = event[1].gsub(/{|}/, "").split("|")
            tbl << [action, event[2], message_insertions[2],message_insertions[4]]
        end
        
    end
    print_line tbl.to_s
  end
end