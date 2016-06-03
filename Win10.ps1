##########
# Win10 Initial Setup Script
# GUI Version: PeterBay <pb.pb@centrum.cz>
# Version: 1.1, 2016-06-01
##########
# Original Author: Disassembler <disassembler@dasm.cz>
# Based on version: 1.4, 2016-01-16
##########


$settings = @{
	"Privacy Settings" = @{
		"telemetry" = @{ "name" = "Telemetry"; "default" = "disable" }
	    "wifi_sense" = @{ "name" = "Wi-Fi Sense"; "default" = "disable" }
	    "smartscreen_filter" = @{ "name" = "SmartScreen Filter"; "default" = "disable" }
	    "bingsearch_startmenu" = @{ "name" = "Bing Search in Start Menu"; "default" = "disable" }
	    "location_tracking" = @{ "name" = "Location Tracking"; "default" = "disable" }
	    "feedback" = @{ "name" = "Feedback"; "default" = "disable" }
	    "advertising_id" = @{ "name" = "Advertising ID"; "default" = "disable" }
	    "cortana" = @{ "name" = "Cortana"; "default" = "disable" }
	    "windows_update_p2p" = @{ "name" = "Windows Update P2P only to local network"; "default" = "disable" }
	    "remove_autologger_file" = @{ "name" = "AutoLogger file and restrict directory"; "default" = "disable" }
	    "diagnostics_tracking" = @{ "name" = "Diagnostics Tracking Service"; "default" = "disable" }
	    "wap_push_service" = @{ "name" = "WAP Push Service"; "default" = "disable" }
	}
	"Service Tweaks"  = @{
	    "uac_level" = @{ "name" = "UAC level"; "default" = "disable" }
	    "sharing_mapped_drives" = @{ "name" = "Sharing mapped drives between users"; "default" = "enable" }
	    "firewall" = @{ "name" = "Firewall"; "default" = "disable" }
	    "windows_defender" = @{ "name" = "Windows Defender"; "default" = "disable" }
	    "windows_update_restart" = @{ "name" = "Windows Update automatic restart"; "default" = "disable" }
	    "home_groups_services" = @{ "name" = "Home Groups services"; "default" = "disable" }
	    "remote_assistance" = @{ "name" = "Remote Assistance"; "default" = "disable" }
	    "windows_desktop_wo_nla" = @{ "name" = "Remote Desktop w/o Network Level Authentication"; "default" = "enable" }
  	}
  	"UI Tweaks" = @{
	    "action_center" = @{ "name" = "Action Center"; "default" = "disable" }
	    "lock_screen" = @{ "name" = "Lock screen"; "default" = "disable" }
	    "autoplay" = @{ "name" = "Autoplay"; "default" = "disable" }
	    "autorun_all_drives" = @{ "name" = "Autorun for all drives"; "default" = "disable" }
	    "sticky _keys_prompt" = @{ "name" = "Sticky keys prompt"; "default" = "disable" }
	    "search_button_box" = @{ "name" = "Search button / box"; "default" = "disable" }
	    "task_view_button" = @{ "name" = "Task View button"; "default" = "disable" }
	    "small_icons_in_taskbar" = @{ "name" = "Small icons in taskbar"; "default" = "enable" }
	    "titles_in_taskbar" = @{ "name" = "Titles in taskbar"; "default" = "enable" }
	    "all_tray_icons" = @{ "name" = "All tray icons"; "default" = "enable" }
	    "known_file_extension" = @{ "name" = "Known file extensions"; "default" = "enable" }
	    "hidden_files" = @{ "name" = "Hidden files"; "default" = "enable" }
	    "default_explorer_view" = @{ "name" = "Change default Explorer view to `"Computer`""; "default" = "enable" }
	    "computer_shortcut_on_desktop" = @{ "name" = "Show Computer shortcut on desktop"; "default" = "enable" }
	    "desktop_icon_from_computer_namespace" = @{ "name" = "Desktop icon from computer namespace"; "default" = "disable" }
	    "documents_icon_from_computer_namespace" = @{ "name" = "Documents icon from computer namespace"; "default" = "disable" }
	    "downloads_icon_from_computer_namespace" = @{ "name" = "Downloads icon from computer namespace"; "default" = "disable" }
	    "music_icon_from_computer_namespace" = @{ "name" = "Music icon from computer namespace"; "default" = "disable" }
	    "picture_icon_from_computer_namespace" = @{ "name" = "Pictures icon from computer namespace"; "default" = "disable" }
	    "videos_icon_from_computer_namespace" = @{ "name" = "Videos icon from computer namespace"; "default" = "disable" }
	    "secondary_us_keyboard" = @{ "name" = "Secondary en-US keyboard"; "default" = "enable" }
  	}
  	"Unwanted applications" = @{
	    "onedrive" = @{ "name" = "OneDrive"; "default" = "" }
	    "onedrive_uninstall_install" = @{ "name" = "OneDrive uninstall | install"; "default" = "" }
	    "Microsoft.3DBuilder" = @{ "name" = "Microsoft 3D Builder"; "default" = "" }
	    "Microsoft.BingFinance" = @{ "name" = "Microsoft Bing Finance"; "default" = "" }
	    "Microsoft.BingNews" = @{ "name" = "Microsoft Bing News"; "default" = "" }
	    "Microsoft.BingSports" = @{ "name" = "Microsoft Bing Sports"; "default" = "" }
	    "Microsoft.BingWeather" = @{ "name" = "Microsoft Bing Weather"; "default" = "" }
	    "Microsoft.Getstarted" = @{ "name" = "Microsoft Getstarted"; "default" = "" }
	    "Microsoft.MicrosoftOfficeHub" = @{ "name" = "Microsoft Microsoft Office Hub"; "default" = "" }
	    "Microsoft.MicrosoftSolitaireCollection" = @{ "name" = "Microsoft Microsoft Solitaire Collection"; "default" = "" }
	    "Microsoft.Office.OneNote" = @{ "name" = "Microsoft Office OneNote"; "default" = "" }
	    "Microsoft.People" = @{ "name" = "Microsoft People"; "default" = "" }
	    "Microsoft.SkypeApp" = @{ "name" = "Microsoft SkypeApp"; "default" = "" }
	    "Microsoft.Windows.Photos" = @{ "name" = "Microsoft Windows Photos"; "default" = "" }
	    "Microsoft.WindowsAlarms" = @{ "name" = "Microsoft WindowsAlarms"; "default" = "" }
	    "Microsoft.WindowsCamera" = @{ "name" = "Microsoft WindowsCamera"; "default" = "" }
	    "microsoft.windowscommunicationsapps" = @{ "name" = "Microsoft Windows Communications Apps"; "default" = "" }
	    "Microsoft.WindowsMaps" = @{ "name" = "Microsoft Windows Maps"; "default" = "" }
	    "Microsoft.WindowsPhone" = @{ "name" = "Microsoft Windows Phone"; "default" = "" }
	    "Microsoft.WindowsSoundRecorder" = @{ "name" = "Microsoft Windows Sound Recorder"; "default" = "" }
	    "Microsoft.XboxApp" = @{ "name" = "Microsoft Xbox App"; "default" = "" }
	    "Microsoft.ZuneMusic" = @{ "name" = "Microsoft Zune Music"; "default" = "" }
	    "Microsoft.ZuneVideo" = @{ "name" = "Microsoft Zune Video"; "default" = "" }
	    "Microsoft.AppConnector" = @{ "name" = "Microsoft App Connector"; "default" = "" }
	    "Microsoft.ConnectivityStore" = @{ "name" = "Microsoft Connectivity Store"; "default" = "" }
	    "Microsoft.Office.Sway" = @{ "name" = "Microsoft Office Sway"; "default" = "" }
	    "Microsoft.Messaging" = @{ "name" = "Microsoft Messaging"; "default" = "" }
		"Microsoft.CommsPhone" = @{ "name" = "Microsoft Comms Phone"; "default" = "" }
		"Twitter" = @{ "name" = "Twitter"; "default" = "" }
		"CandyCrushSodaSaga" = @{ "name" = "Candy Crush Soda Saga"; "default" = "" }
		"windows_media_player" = @{ "name" = "Windows Media Player"; "default" = "" }
		"work_folders_client" = @{ "name" = "Work Folders Client"; "default" = "" }
	}
	"Cleaning" = @{
		"temp_files" = @{ "name" = "Cleaning Temp folders"; "default" = "enable" }
		"ie_temp_files" = @{ "name" = "Cleaning IE Temp files"; "default" = "enable" }
	}
}

$checkboxes = @{}


function disableFeature ( $key ){

	Write-Host "DISABLE: " + $key 
	
	switch ($key) 
    { 
        "telemetry" {
			Write-Host "Disabling Telemetry..."
			Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
		} 
		
		"wifi_sense" {
			Write-Host "Disabling Wi-Fi Sense..."
			If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
				New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
		}
		
		"smartscreen_filter" {
			Write-Host "Disabling SmartScreen Filter..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
		}
		
		"bingsearch_startmenu" {
			Write-Host "Disabling Bing Search in Start Menu..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
		
		}
		
		"location_tracking" {
			Write-Host "Disabling Location Tracking..."
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
		}
		
		"feedback" {
			Write-Host "Disabling Feedback..."
			If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
				New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
		}
		
		"advertising_id" {
			Write-Host "Disabling Advertising ID..."
			If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
		}
		
		"cortana" {
			Write-Host "Disabling Cortana..."
			If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
				New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
			If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
				New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
			If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
				New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
		}
		
		"windows_update_p2p" {
			Write-Host "Restricting Windows Update P2P only to local network..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
			If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3
		}
		
		"remove_autologger_file" {
			Write-Host "Removing AutoLogger file and restricting directory..."
			$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
			If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
				Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
			}
			icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
		}
		
		"diagnostics_tracking" {
			Write-Host "Stopping and disabling Diagnostics Tracking Service..."
			Stop-Service "DiagTrack"
			Set-Service "DiagTrack" -StartupType Disabled
		}
		
		"wap_push_service" {
			Write-Host "Stopping and disabling WAP Push Service..."
			Stop-Service "dmwappushservice"
			Set-Service "dmwappushservice" -StartupType Disabled
		}
		
		"uac_level" {
			Write-Host "Lowering UAC level..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
		}
		
		"windows_defender" {
			Write-Host "Disabling Windows Defender..."
			Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
		}
		
		"windows_update_restart" {
			Write-Host "Disabling Windows Update automatic restart..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
		}
		
		"home_groups_services" {
			Write-Host "Stopping and disabling Home Groups services..."
			Stop-Service "HomeGroupListener"
			Set-Service "HomeGroupListener" -StartupType Disabled
			Stop-Service "HomeGroupProvider"
			Set-Service "HomeGroupProvider" -StartupType Disabled
		}
		
		"remote_assistance" {
			Write-Host "Disabling Remote Assistance..."
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
		}
		
		"sharing_mapped_drives" {
			Write-Host "Disabling sharing mapped drives between users..."
			Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections"
		}
		
		"firewall" {
			Write-Host "Disabling Firewall..."
			Set-NetFirewallProfile -Profile * -Enabled False
		}
		
		"windows_desktop_wo_nla" {
			Write-Host "Disabling Remote Desktop w/o Network Level Authentication..."
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
		}
		
		"action_center" {
			Write-Host "Disabling Action Center..."
			If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
				New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
		}
		
		"lock_screen" {
			Write-Host "Disabling Lock screen..."
			If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization")) {
				New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
		}
		
		"autoplay" {
			Write-Host "Disabling Autoplay..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
		}
		
		"autorun_all_drives" {
			Write-Host "Disabling Autorun for all drives..."
			If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
		}
		
		"sticky _keys_prompt" {
			Write-Host "Disabling Sticky keys prompt..."
			Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
		}
		
		"search_button_box" {
			Write-Host "Hidding Search Box / Button..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
		}
		
		"task_view_button" {
			Write-Host "Hidding Task View button..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
		}
		
		"small_icons_in_taskbar" {
			Write-Host "Showing large icons in taskbar..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons"
		}
		
		"titles_in_taskbar" {
			Write-Host "Hidding titles in taskbar..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel"
		}
		
		"all_tray_icons" {
			Write-Host "Hidding all tray icons..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray"
		}
		
		"known_file_extension" { 
			Write-Host "Hidding known file extensions..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
		}
		
		"hidden_files" {
			Write-Host "Hidding hidden files..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
		}
		
		"default_explorer_view" {
			Write-Host "Changing default Explorer view to `"Quick Access`"..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo"
		}
		
		"computer_shortcut_on_desktop" {
			Write-Host "Hidding Computer shortcut on desktop..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
		}
		
		"desktop_icon_from_computer_namespace" {
			Write-Host "Removing Desktop icon from computer namespace..."
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
		}
		
		"documents_icon_from_computer_namespace" {
			Write-Host "Removing Documents icon from computer namespace..."
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
		}
		
		"downloads_icon_from_computer_namespace" {
			Write-Host "Removing Downloads icon from computer namespace..."
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
		}
		
		"music_icon_from_computer_namespace" {
			Write-Host "Removing Music icon from computer namespace..."
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
		}
		
		"picture_icon_from_computer_namespace" {
			Write-Host "Removing Pictures icon from computer namespace..."
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
		}
		
		"videos_icon_from_computer_namespace" {
			Write-Host "Removing Videos icon from computer namespace..."
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
		}
		
		"secondary_us_keyboard" {
			Write-Host "Removing secondary en-US keyboard..."
			$langs = Get-WinUserLanguageList
			Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-US"}) -Force
		}
		
		"onedrive" {
			Write-Host "Disabling OneDrive..."
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
		}
		
		"onedrive_uninstall_install" {
			Write-Host "Uninstalling OneDrive..."
			Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
			Start-Sleep -s 3
			$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
			If (!(Test-Path $onedrive)) {
				$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
			}
			Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
			Start-Sleep -s 3
			Stop-Process -Name explorer -ErrorAction SilentlyContinue
			Start-Sleep -s 3
			Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
			Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
			Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
			If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
				Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
			}
			If (!(Test-Path "HKCR:")) {
				New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
			}
			Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
		}
		
		"ms_3DBuilder" {
			Write-Host "Uninstalling Microsoft.3DBuilder"
			Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
 		}
		
		"ms_BingFinance" {
 			Write-Host "Uninstalling Microsoft.BingFinance"
			Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
 		}

		"ms_BingNews" {
 			Write-Host "Uninstalling Microsoft.BingNews"
			Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
 		}
		
		"ms_BingSports" {
 			Write-Host "Uninstalling Microsoft.BingSports"
			Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
 		}
		
		"ms_BingWeather" {
 			Write-Host "Uninstalling Microsoft.BingWeather"
			Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
 		}
		
		"ms_Getstarted" {
 			Write-Host "Uninstalling Microsoft.Getstarted"
			Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
		}
		
		"ms_MicrosoftOfficeHub" {
 			Write-Host "Uninstalling Microsoft.MicrosoftOfficeHub"
			Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
 		}
		
		"ms_MicrosoftSolitaireCollection" {
 			Write-Host "Uninstalling Microsoft.MicrosoftSolitaireCollection"
			Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
 		}
		
		"ms_Office.OneNote" {
 			Write-Host "Uninstalling Microsoft.Office.OneNote"
			Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
 		}

		"ms_People" {
 			Write-Host "Uninstalling Microsoft.People"
			Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
 		}

		"ms_SkypeApp" {
 			Write-Host "Uninstalling Microsoft.SkypeApp"
			Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
 		}

		"ms_Windows.Photos" {
 			Write-Host "Uninstalling Microsoft.Windows.Photos"
			Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
 		}

		"ms_WindowsAlarms" {
 			Write-Host "Uninstalling Microsoft.WindowsAlarms"
			Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
 		}

		"ms_WindowsCamera" {
 			Write-Host "Uninstalling Microsoft.WindowsCamera"
			Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
 		}

		"ms_windowscommunicationsapps" {
 			Write-Host "Uninstalling microsoft.windowscommunicationsapps"
			Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
 		}
		
		"ms_WindowsMaps" {
 			Write-Host "Uninstalling Microsoft.WindowsMaps"
			Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
 		}

		"ms_WindowsPhone" {
 			Write-Host "Uninstalling Microsoft.WindowsPhone"
			Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
 		}

		"ms_WindowsSoundRecorder" {
 			Write-Host "Uninstalling Microsoft.WindowsSoundRecorder"
			Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
 		}

		"ms_XboxApp" {
 			Write-Host "Uninstalling Microsoft.XboxApp"
			Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
 		}

		"ms_ZuneMusic" {
 			Write-Host "Uninstalling Microsoft.ZuneMusic"
			Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
 		}

		"ms_ZuneVideo" {
 			Write-Host "Uninstalling Microsoft.ZuneVideo"
			Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
 		}

		"ms_AppConnector" {
 			Write-Host "Uninstalling Microsoft.AppConnector"
			Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
 		}
	
		"ms_ConnectivityStore" {
 			Write-Host "Uninstalling Microsoft.ConnectivityStore"
			Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
 		}

		"ms_Office.Sway" {
 			Write-Host "Uninstalling Microsoft.Office.Sway"
			Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
 		}

		"ms_Messaging" {
 			Write-Host "Uninstalling Microsoft.Messaging"
			Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
 		}

		"ms_CommsPhone" {
 			Write-Host "Uninstalling Microsoft.CommsPhone"
			Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
 		}

		"Twitter" {
 			Write-Host "Uninstalling 9E2F88E3.Twitter"
			Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
 		}

		"CandyCrushSodaSaga" {
 			Write-Host "Uninstalling king.com.CandyCrushSodaSaga"
			Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
 		}
		
		"windows_media_player" { 
			Write-Host "Uninstalling Windows Media Player..."
			dism /online /Disable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart
		}
		
		"work_folders_client" { 
			Write-Host "Uninstalling Work Folders Client..."
			dism /online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart
		}
		

	}

}

function enableFeature ( $key ){

	Write-Host "ENABLE: " + $key
	
	switch ($key) 
    { 
        "telemetry" {
			Write-Host "Enabling Telemetry..."
			Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
		}
		
		"wifi_sense" {
			Write-Host "Enabling Wi-Fi Sense..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
		}
		
		"smartscreen_filter" {
			Write-Host "Enabling SmartScreen Filter..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"
		}
		
		"bingsearch_startmenu" {
			Write-Host "Enabling Bing Search in Start Menu..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled"
		
		}
		
		"location_tracking" {
			Write-Host "Enabling Location Tracking..."
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1
		}
		
		"feedback" {
			Write-Host "Enabling Feedback..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"
		}
		
		"advertising_id" {
			Write-Host "Enabling Advertising ID..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled"
		}
		
		"cortana" {
			Write-Host "Enabling Cortana..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy"
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts"
		}

		"windows_update_p2p" {
			Write-Host "Unrestricting Windows Update P2P only to local network..."
			Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode"
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode"
		}
		
		"remove_autologger_file" {
			Write-Host "Add AutoLogger file and restricting directory..."
			$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
			icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null
		}
		
		"diagnostics_tracking" {
			Write-Host "Enable and start Diagnostics Tracking Service..."
			Set-Service "DiagTrack" -StartupType Automatic
			Start-Service "DiagTrack"
		}
		
		"wap_push_service" {
			Write-Host "Enable and start WAP Push Service..."
			Set-Service "dmwappushservice" -StartupType Automatic
			Start-Service "dmwappushservice"
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1
		}
		
		"uac_level" {
			Write-Host "Raising UAC level..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
		}
		
		"windows_defender" {
			Write-Host "Enabling Windows Defender..."
			Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
		}
		
		"windows_update_restart" {
			Write-Host "Enabling Windows Update automatic restart..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 0
		}
		
		"home_groups_services" {
			Write-Host "Enable and start Home Groups services..."
			Set-Service "HomeGroupListener" -StartupType Manual
			Set-Service "HomeGroupProvider" -StartupType Manual
			Start-Service "HomeGroupProvider"
		}
		
		"remote_assistance" {
			Write-Host "Enabling Remote Assistance..."
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
		}
		
		"sharing_mapped_drives" {
			Write-Host "Enabling sharing mapped drives between users..."
			Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
		}
		
		"firewall" {
			Write-Host "Enabling Firewall..."
			Set-NetFirewallProfile -Profile * -Enabled True
		}
		
		"windows_desktop_wo_nla" {
			Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
		}
		
		"action_center" {
			Write-Host "Enabling Action Center..."
			Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter"
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled"
		}
		
		"lock_screen" {
			Write-Host "Enabling Lock screen..."
			Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen"
		}
		
		"autoplay" {
			Write-Host "Enabling Autoplay..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
		}
		
		"autorun_all_drives" {
			Write-Host "Enabling Autorun for all drives..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun"
		}
		
		"sticky _keys_prompt" {
			Write-Host "Enabling Sticky keys prompt..."
			Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
		}
		
		"search_button_box" {
			Write-Host "Hiding Search Box / Button..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode"
		}
		
		"task_view_button" {
			Write-Host "Hiding Task View button..."
			Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton"
		}
		
		"small_icons_in_taskbar" {
			Write-Host "Showing large icons in taskbar..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
		}
		
		"titles_in_taskbar" {
			Write-Host "Hiding titles in taskbar..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
		}
		
		"all_tray_icons" {
			Write-Host "Hiding all tray icons..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
		}
		
		"known_file_extension" { 
			Write-Host "Showing known file extensions..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
		}
		
		"hidden_files" {
			Write-Host "Showing hidden files..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
		}
		
		"default_explorer_view" {
			Write-Host "Changing default Explorer view to `"Computer`"..."
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
		}
		
		"computer_shortcut_on_desktop" {
			Write-Host "Showing Computer shortcut on desktop..."
			If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
				New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
			Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0		
		}
		
		"desktop_icon_from_computer_namespace" {
			Write-Host "Adding Desktop icon from computer namespace..."
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
		}
		
		"documents_icon_from_computer_namespace" {
			Write-Host "Adding Documents icon from computer namespace..."
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
		}
		
		"downloads_icon_from_computer_namespace" {
			Write-Host "Adding Downloads icon from computer namespace..."
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
		}
		
		"music_icon_from_computer_namespace" {
			Write-Host "Adding Music icon from computer namespace..."
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
		}
		
		"picture_icon_from_computer_namespace" {
			Write-Host "Adding Pictures icon from computer namespace..."
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
		}
		
		"videos_icon_from_computer_namespace" {
			Write-Host "Adding Videos icon from computer namespace..."
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
			New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
		}
		
		"secondary_us_keyboard" {
			Write-Host "Adding secondary en-US keyboard..."
			$langs = Get-WinUserLanguageList
			$langs.Add("en-US")
			Set-WinUserLanguageList $langs -Force
		}
		
		"onedrive" {
			Write-Host "Enabling OneDrive..."
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC"
		}
		
		"onedrive_uninstall_install" {
			Write-Host "Installing OneDrive..."
			$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
			If (!(Test-Path $onedrive)) {
				$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
			}
			Start-Process $onedrive -NoNewWindow
		}
		
		"ms_3DBuilder" {
 			Write-Host "Installing Microsoft.3DBuilder"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.3DBuilder").InstallLocation)AppXManifest.xml"
 		}
		
		"ms_BingFinance" {
 			Write-Host "Installing Microsoft.BingFinance"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingFinance").InstallLocation)AppXManifest.xml"
 		}

		"ms_BingNews" {
 			Write-Host "Installing Microsoft.BingNews"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingNews").InstallLocation)AppXManifest.xml"
 		}

		"ms_BingSports" {
 			Write-Host "Installing Microsoft.BingSports"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingSports").InstallLocation)AppXManifest.xml"
 		}

		"ms_BingWeather" {
 			Write-Host "Installing Microsoft.BingWeather"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingWeather").InstallLocation)AppXManifest.xml"
 		}
		
		"ms_Getstarted" {
 			Write-Host "Installing Microsoft.Getstarted"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Getstarted").InstallLocation)AppXManifest.xml"
 		}

		"ms_MicrosoftOfficeHub" {
 			Write-Host "Installing Microsoft.MicrosoftOfficeHub"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftOfficeHub").InstallLocation)AppXManifest.xml"
 		}

		"ms_MicrosoftSolitaireCollection" {
 			Write-Host "Installing Microsoft.MicrosoftSolitaireCollection"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection").InstallLocation)AppXManifest.xml"
 		}

		"ms_Office.OneNote" {
			Write-Host "Installing Microsoft.Office.OneNote"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.OneNote").InstallLocation)AppXManifest.xml"
 		}

		"ms_People" {
 			Write-Host "Installing Microsoft.People"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.People").InstallLocation)AppXManifest.xml"
 		}

		"ms_SkypeApp" {
 			Write-Host "Installing Microsoft.SkypeApp"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.SkypeApp").InstallLocation)AppXManifest.xml"
 		}

		"ms_Windows.Photos" {
 			Write-Host "Installing Microsoft.Windows.Photos"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Windows.Photos").InstallLocation)AppXManifest.xml"
 		}

		"ms_WindowsAlarms" {
 			Write-Host "Installing Microsoft.WindowsAlarms"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsAlarms").InstallLocation)AppXManifest.xml"
 		}

		"ms_WindowsCamera" {
 			Write-Host "Installing Microsoft.WindowsCamera"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsCamera").InstallLocation)AppXManifest.xml"
 		}

		"ms_windowscommunicationsapps" {
 			Write-Host "Installing microsoft.windowscommunicationsapps"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "microsoft.windowscommunicationsapps").InstallLocation)AppXManifest.xml"
 		}

		"ms_WindowsMaps" {
 			Write-Host "Installing Microsoft.WindowsMaps"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsMaps").InstallLocation)AppXManifest.xml"
 		}

		"ms_WindowsPhone" {
 			Write-Host "Installing Microsoft.WindowsPhone"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsPhone").InstallLocation)AppXManifest.xml"
 		}

		"ms_WindowsSoundRecorder" {
 			Write-Host "Installing Microsoft.WindowsSoundRecorder"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsSoundRecorder").InstallLocation)AppXManifest.xml"
 		}

		"ms_XboxApp" {
 			Write-Host "Installing Microsoft.XboxApp"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.XboxApp").InstallLocation)AppXManifest.xml"
 		}

		"ms_ZuneMusic" {
 			Write-Host "Installing Microsoft.ZuneMusic"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneMusic").InstallLocation)AppXManifest.xml"
 		}

		"ms_ZuneVideo" {
 			Write-Host "Installing Microsoft.ZuneVideo"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneVideo").InstallLocation)AppXManifest.xml"
 		}

		"ms_AppConnector" {
 			Write-Host "Installing Microsoft.AppConnector"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.AppConnector").InstallLocation)AppXManifest.xml"
 		}
	
		"ms_ConnectivityStore" {
			 Write-Host "Installing Microsoft.ConnectivityStore"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ConnectivityStore").InstallLocation)AppXManifest.xml"
 		}

		"ms_Office.Sway" {
 			Write-Host "Installing Microsoft.Office.Sway"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.Sway").InstallLocation)AppXManifest.xml"
 		}

		"ms_Messaging" {
 			Write-Host "Installing Microsoft.Messaging"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Messaging").InstallLocation)AppXManifest.xml"
 		}

		"ms_CommsPhone" {
 			Write-Host "Installing Microsoft.CommsPhone"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.CommsPhone").InstallLocation)AppXManifest.xml"
 		}

		"Twitter" {
 			Write-Host "Installing 9E2F88E3.Twitter"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "9E2F88E3.Twitter").InstallLocation)AppXManifest.xml"
 		}

		"CandyCrushSodaSaga" {
 			Write-Host "Installing king.com.CandyCrushSodaSaga"
			Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "king.com.CandyCrushSodaSaga").InstallLocation)AppXManifest.xml"
 		}
		
		"windows_media_player" { 
			Write-Host "Installing Windows Media Player..."
			dism /online /Enable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart
		}
		
		"work_folders_client" { 
			Write-Host "Installing Work Folders Client..."
			dism /online /Enable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart
		}
		
		"temp_files" {
			Get-ChildItem $env:tmp -Recurse | Remove-Item -Recurse -force -ErrorAction SilentlyContinue
			Get-ChildItem ([environment]::GetEnvironmentVariable("temp","machine")) -Recurse| Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
		}
		
		"ie_temp_files" {
			RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 8
		}
		
	}

}

function SystemDrawingSize ( [Int] $width, [Int] $height ) {
	$System_Drawing_Size = New-Object System.Drawing.Size
	$System_Drawing_Size.Width  = $width
	$System_Drawing_Size.Height = $height
	return $System_Drawing_Size
}

function SystemDrawingPoint ( [Int] $x, [Int] $y ){
	$System_Drawing_Point = New-Object System.Drawing.Point
	$System_Drawing_Point.X = [Int] $x
	$System_Drawing_Point.Y = [Int] $y
	return $System_Drawing_Point
}

function addCheckbox ( $x, $y, $name, $text  ){

	$checkBox = New-Object System.Windows.Forms.CheckBox
    $checkBox.UseVisualStyleBackColor = $True
    $checkBox.Size = SystemDrawingSize 60 24
    $checkBox.Location = SystemDrawingPoint $x $y
    $checkBox.DataBindings.DefaultDataSourceUpdateMode = 0
    $checkBox.Name = $name
    $checkBox.Text = $text
	return $checkBox
}

function addCheckRow ( $form, $x, $y, $name, $settings){

	$uName = "disable_" + $name
	$iName = "enable_" + $name

	$xDisable = $x + 10
	$xEnable  = $x + 70
	$xLabel   = $x + 130

	$checkDisable = addCheckbox $xDisable $y $uName "disable"
	$checkEnable   = addCheckbox $xEnable $y $iName "enable"

	$checkboxes[ $name ] = @{ "enable" = $checkEnable; "disable" = $checkDisable }

	if ( $settings["default"] -eq "enable" ){
		$checkEnable.Checked = $true
	} elseif ( $settings["default"] -eq "disable" ) {
		$checkDisable.Checked = $true
	}
	
	$textY = $y + 5

	$textBox = New-Object System.Windows.Forms.Label
    #$textBox.UseVisualStyleBackColor = $True
    $textBox.Size = SystemDrawingSize 280 24
    $textBox.Location = SystemDrawingPoint $xLabel $textY
    $textBox.DataBindings.DefaultDataSourceUpdateMode = 0
    $textBox.Name = "label_" + $name
    $textBox.Text = "- " + $settings["name"]

	$form.Controls.Add( $checkDisable )
	$form.Controls.Add( $checkEnable )
	$form.Controls.Add( $textBox )

}


	# Ask for elevated permissions if required
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
		Exit
	}

	$windowWidth = 1200
	$windowHeight = 768
	
	$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState

	[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
	[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null

	$handler_button1_Click = 
	{

		Write-Host "--- BEGIN ---------------------------"

		$checkboxes.Keys | % {

			if ( $checkboxes.Item($_)["disable"].Checked ){
				disableFeature $_
			}

			if ( $checkboxes.Item($_)["enable"].Checked ){
				enableFeature $_
			}
		}
		
		Write-Host "--- END -----------------------------"
		
	}

	$OnLoadForm_StateCorrection =
	{#Correct the initial state of the form to prevent the .Net maximized form issue
	    $form1.WindowState = $InitialFormWindowState
	}

	#----------------------------------------------
	#region Generated Form Code
	$form1 = New-Object System.Windows.Forms.Form
	$form1.Text = "Win 10 Tweaker"
	$form1.Name = "form1"
	$form1.DataBindings.DefaultDataSourceUpdateMode = 0
	$form1.ClientSize = SystemDrawingSize $windowWidth $windowHeight

	$button1 = New-Object System.Windows.Forms.Button
	#$button1.TabIndex = 4
	$button1.Name = "button_run"
	$button1.Size = SystemDrawingSize 75 23
	#$button1.UseVisualStyleBackColor = $True
	$button1.Text = "Run Script"

	$buttonLeft = $windowWidth - 100
	$buttonTop  = $windowHeight - 40
	
	$button1.Location = SystemDrawingPoint $buttonLeft $buttonTop
	$button1.DataBindings.DefaultDataSourceUpdateMode = 0
	$button1.add_Click( $handler_button1_Click )
	
	$form1.Controls.Add($button1)

	$y = 10
	$x = 0

	#$settings.Keys | % {
	
	$settings.GetEnumerator() | sort -Property name | % {

		$sectionName = $_.Name
		$sectionContent = $_.Value

		$labelX = $x + 10
		$lavelY = $y + 5

		$textBox = New-Object System.Windows.Forms.Label
	    #$textBox.UseVisualStyleBackColor = $True
	    $textBox.Size     = SystemDrawingSize 300 24
	    $textBox.Location = SystemDrawingPoint $labelX $lavelY
	    $textBox.DataBindings.DefaultDataSourceUpdateMode = 0
	    $textBox.Name = "label_" + $sectionName
	    $textBox.Text = " ==== " + $sectionName + " ==== "

		$form1.Controls.Add( $textBox )

		$y += 25
		if ( $y -gt $windowHeight - 60 ){
			$x = $x + 400
			$y = 10
		}

		$sectionContent.GetEnumerator() | sort -Property name | %{
			addCheckRow $form1 $x $y $_.Name $_.Value
			$y += 25

			if ( $y -gt $windowHeight - 60 ){
				$x = $x + 400
				$y = 10
			}
		}

	}

	#Save the initial state of the form
	$InitialFormWindowState = $form1.WindowState
	#Init the OnLoad event to correct the initial state of the form
	$form1.add_Load($OnLoadForm_StateCorrection)
	#Show the Form
	$form1.ShowDialog()| Out-Null


