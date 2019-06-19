module Msf
class Plugin::HoneyBadger < Msf::Plugin

  # Post Exploitation command class
  ################################################################################################
  class SituationalAwarenessCommandDispatcher

    include Msf::Auxiliary::Report
    include Msf::Ui::Console::CommandDispatcher

    def name
      "situational_awareness"
    end

    def commands
      {
        'host_survey'       => "Run modules for gathering info of a host against specified sessions."
      }
    end

    def cmd_host_survey(*args)
      opts = Rex::Parser::Arguments.new(
        "-s"   => [ true, "Sessions to run modules against. Example <all> or <1,2,3,4>"],
        "-h"   => [ false,  "Command Help"]
      )
      # Parse options
      if args.length == 0
        print_line(opts.usage)
        return
      end
      sessions = ""

      opts.parse(args) do |opt, idx, val|
        case opt
        when "-s"
          sessions = val
        when "-h"
          print_line(opts.usage)
          return
        else
          print_line(opts.usage)
          return
        end
      end

      post_mods = [
        {"mod" => "windows/gather/ts_host_info", "opt" => nil},
        {"mod" => "windows/gather/ts_check_vm", "opt" => nil},
        {"mod" => "windows/gather/ts_get_policyinfo", "opt" => nil},
        {"mod" => "windows/gather/ts_dangerous_processes", "opt" => nil},
        {"mod" => "windows/gather/ts_collect_services", "opt" => nil},
        {"mod" => "windows/gather/ts_ps_controls", "opt" => nil},
        {"mod" => "windows/gather/ts_wsh_controls", "opt" => nil},
        {"mod" => "windows/gather/ts_wmi_securitycenter", "opt" => nil}]

      if not sessions.empty?
        post_mods.each do |p|
          m = framework.post.create(p["mod"])
          next if m == nil

          # Set Sessions to be processed
          if sessions =~ /all/i
            session_list = m.compatible_sessions
          else
            session_list = sessions.split(",")
          end
          session_list.each do |s|
            begin
              if m.session_compatible?(s.to_i)
                m.datastore['SESSION'] = s.to_i
                if p['opt']
                  opt_pair = p['opt'].split("=",2)
                  m.datastore[opt_pair[0]] = opt_pair[1]
                end
                m.options.validate(m.datastore)
                print_line("")
                print_line("Running #{p['mod']} against #{s}")
                m.run_simple(
                  'LocalInput'  => driver.input,
                  'LocalOutput' => driver.output
                )
              end
            rescue
              print_error("Could not run post module against sessions #{s}.")
            end
          end
        end
      else
        print_line(opts.usage)
        return
      end
    end
  end
  #-------------------------------------------------------------------------------------------------
  def initialize(framework, opts)
    super
    if framework.db and framework.db.active
      add_console_dispatcher(SituationalAwarenessCommandDispatcher)
      print_line "Version 0.1-Dev"
      print_line "HoneyBadger plugin loaded."
      print_line "by Carlos Perez (carlos.perez[at]trustedsec.com)"
    else
      print_error("This plugin requires the framework to be connected to a Database!")
    end
  end

  def cleanup
    remove_console_dispatcher('situational_awareness')
  end

  def name
    "honeybadger"
  end

  def desc
    "TrustedSec Metasploit Automation Plugin."
  end

protected
end
end