# encoding: UTF-8

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'csv'



class MetasploitModule < Msf::Post
    include Msf::Auxiliary::Report
    include Msf::Post::Windows::Registry
    include Msf::Post::Windows::ExtAPI
    include Msf::Post::File
  
    def initialize(info = {})
      super(update_info(
          info,
          'Name'          => 'Windows Gather AD Enumerate Domain Group Policy Objects',
          'Description'   => %q{ This Module will enumerate the audit policy and GPOs applied to 
           a host through a Windows Meterpreter Session.},
          'License'       => BSD_LICENSE,
          'Author'        => [ 'Carlos Perez <carlos.perez[at]trustedsec.com>' ],
          'Platform'      => ['win'],
          'SessionTypes'  => ['meterpreter']
        ))
      register_options(
        [
          OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false])
        ], self.class)
    end
  
    # Run Method for when run command is issued
    def run
      print_status("Running module against #{ sysinfo['Computer'] }")
    
      domain = get_domain()
      return if domain.nil?
      print_status("Host is part of #{domain}")
      get_gpo_info()
      tradecraft_check(find_audit(domain))
      
    end
  
    # get GPO information
    def get_gpo_info()
        # Enumerate GPOs applied to the machine
        gpo_key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\DataStore\Machine\0'
        gpo_key_list = registry_enumkeys(gpo_key)

        applied_gpo = []
        # pull information on each GPO
        gpo_key_list.each do |gpo|
          gpo_info = {}
          applied_gpo_key = "#{gpo_key}\\#{gpo}"
          gpo_info[:guid] = registry_getvaldata(applied_gpo_key, 'GPOName')
          gpo_info[:name] = registry_getvaldata(applied_gpo_key, 'DisplayName')
          gpo_info[:link] = registry_getvaldata(applied_gpo_key, 'Link')
          gpo_info[:path] = registry_getvaldata(applied_gpo_key, 'FileSysPath')
          gpo_info[:dn] = registry_getvaldata(applied_gpo_key, 'DSPath')
          gpo_info[:extensions] = registry_getvaldata(applied_gpo_key, 'Extensions')
          applied_gpo << gpo_info
        end

        print_status("GPOs applied to host:")
        applied_gpo.each do |gpo|
          print_good("\tName: #{gpo[:name]}")
          print_good("\tGUID: #{gpo[:guid]}")
          print_good("\tLink: #{gpo[:link]}")
          print_good("\tDN: #{gpo[:dn]}")
          print_good("\tExtensions: #{gpo[:extensions]}")
          print_good("\tPath: #{gpo[:path]}")
          print_line
        end
        
    end

    # checks the audit settings and warns on common tradecraft actions that may be logged. 
    def tradecraft_check(audit)
        print_status("Tradecraft Notes:")
        if audit.key?("Audit Other Object Access Events") 
            print_warning("\tScheduled task actions are audited.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.schtask',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )

            print_warning("\tFile, Registry and Share access can be logged.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.reg_share_access',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )

            print_warning("\tLocal SAM access is audited.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.sam_access',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )
        end

        if audit.key?("Audit Process Creation")  
            print_warning("\tProcess creation is audited.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.process_creation',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )
        end

        if audit.key?("Audit Security State Change")
            print_warning("\tWindows Startup and Shutdown is logged")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.startup_shutdown',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )
        end

        if audit.key?("Audit Security System Extension")
            print_warning("\tWindows Service creation is logged")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.service_creation',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )
            print_warning("\tAuthentication package install is logged.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.sam_access',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )
            print_warning("\tCode integrity check (file signature does not match).")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.code_integrity_check',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )

        end

        if audit.key?("Audit Audit Policy Change")
            print_warning("\tAudit policy changes are logged.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.audit_policy_change.',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )

        end

        if audit.key?("Audit Special Logon")
            print_warning("\tEvent 4672 logged when highly privileged user logs on.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.high_priv_logon',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )
        end

        if audit.key?("Audit Other Logon/Logoff Events")
            print_warning("\tEvents for screensaver login, console locking, and Remote Desktop connections are logged.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.other_logon',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )
        end

        if audit.key?("Audit Logon")
            print_warning("\tAccount Logon events are logged.")
            report_note(
              :host   => session.session_host,
              :type   => 'host.log.logon',
              :data   => {
                :enabled => true},
              :update => :unique_data
            )
        end

        if audit.key?("Audit Kernel Object")
          print_warning("\tLSASS memory access will be logged in newer versions of Windows (10+/2012 R2+).")
          report_note(
            :host   => session.session_host,
            :type   => 'host.log.kernel_object',
            :data   => {
              :enabled => true},
            :update => :unique_data
          )
      end
        
    end

    # find if there are advanced audit settings and returns a hash table of their settings.
    def find_audit(domain)
        audit = {}
        table = Rex::Text::Table.new(
            'Indent' => 4,
            'SortIndex' => -1,
            'Width' => 80,
            'Columns' =>
            [
              'Audit Category',
              'Setting'
            ]
          )
        windir = client.sys.config.getenv('WINDIR')
        if sysinfo["Architecture"] == session.arch  then
            gpo_path = "#{windir}\\System32\\GroupPolicy\\DataStore\\0\\sysvol\\#{domain}\\Policies"
        else
            gpo_path = "#{windir}\\Sysnative\\GroupPolicy\\DataStore\\0\\sysvol\\#{domain}\\Policies"
        end
        getfile = client.fs.file.search(gpo_path,"audit.csv",recurse=true,timeout=-1)
        if getfile .length > 0 then
            print_status("Advanced Auditing settings found")
            csv_files = []
            getfile.each do |f|
                csv_files << "#{f['path']}\\#{f['name']}"
            end
            csv_files.each do |file|
                csv_content = read_file(file)
                ((csv_content.split("\n"))[2..-1]).each do |l|
                    fields = l.split(",")
                    table << [fields[2], fields[4]]
                    audit["#{fields[2]}"] = fields[4]
                end
            end
            print_line(table.to_s)
        else
            print_status("No advanced auditing settings found.")
        end
        report_note(
          :host => session.session_host,
          :type => 'host.log.settings',
          :data => {
            :settings => table.to_csv
          },
          :update => :unique_data
        )
        return audit
    end



    # get the FQDN of the system domain. 
    def get_domain
      domain = nil
      begin
        subkey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
        v_name = 'DCName'
        domain_dc = registry_getvaldata(subkey, v_name)
      rescue
        print_error 'Could not determine if the host is part of a domain.'
        return nil
      end
      if !domain_dc.nil?
        # lets parse the information
        dom_info =  domain_dc.split('.').drop(1)
        domain = dom_info.join('.')
      else
        print_status 'Host is not part of a domain.'
      end
      domain
    end

  end