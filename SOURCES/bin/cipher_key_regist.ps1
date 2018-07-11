# Powershell needs to run in STA mode to display WPF windows
Param(
[string]$configPath
)

########## Catch internal exception ###########
trap {
	$exmessage = $Error[0] | Out-String
	[System.Windows.Forms.MessageBox]::Show("$exmessage", "Internal error occurred", "OK", "Error", "button1")
	return
}

if ([Threading.Thread]::CurrentThread.GetApartmentState() -eq "MTA"){
	PowerShell -Sta -File $MyInvocation.MyCommand.Path
	return
}

Add-Type -AssemblyName presentationframework -ErrorAction Stop
Add-Type -Assembly System.Windows.Forms -ErrorAction Stop

#########################################################
### Make sure only administrator can run this command ###

function Test-IsAdmin {
	([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]:: GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
} 

#####################################################
#				   Set $env:					   #
#####################################################

$env:PGHOST="localhost"
$env:tdeforpgroot = $PSScriptRoot | %{$_ -replace "bin",""} 
$env:TDE_CURR_NUM_VERSION="1.2.1"
$env:TDE_CURR_VERSION="Free Edition "+ $env:TDE_CURR_NUM_VERSION + ".0"

############## SetUP Status Inform ######################

############### FORM ################
$height = 80
$texbox_left = 210
$label_size = 165
$textbox_size = 190
$button_left = 190
$button_height = 20
$Font = New-Object System.Drawing.Font("MS Gothic",10,[System.Drawing.FontStyle]::Bold)

### main form ###
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
$Form = New-Object System.Windows.Forms.Form 
$Form.Text = "NEC TDE for PG Free Edition V" + $env:TDE_CURR_NUM_VERSION + " Cipher Key Regist"
$Form.Size = New-Object System.Drawing.Size(520,430) 
$Form.StartPosition = "CenterScreen"
$Form.KeyPreview = $True

### NEC label ###
$NECLabel = New-Object System.Windows.Forms.Label
$NECLabel.Location = New-Object System.Drawing.Size(20,25) 
$NECLabel.Size = New-Object System.Drawing.Size(150,30) 
$NECLabel.forecolor = "blue"
$NECLabel.Text = "NEC TDE for PG`nFree Edition V" + $env:TDE_CURR_NUM_VERSION
$NECLabel.Font = $Font
$Form.Controls.Add($NECLabel) 

### general label ###
$GenaralLabel = New-Object System.Windows.Forms.Label
$GenaralLabel.Location = New-Object System.Drawing.Size(20,$height) 
$GenaralLabel.Size = New-Object System.Drawing.Size(280,20) 
$GenaralLabel.Text = "Please enter the information to the following fields:"
$Form.Controls.Add($GenaralLabel) 

$height = $height + 30
### current cipher key label ###
$currentcipherkeylabel = New-Object System.Windows.Forms.Label
$currentcipherkeylabel.Location = New-Object System.Drawing.Size(20,$height) 
$currentcipherkeylabel.Size = New-Object System.Drawing.Size($label_size,20) 
$currentcipherkeylabel.Text = "current cipher key:"
$Form.Controls.Add($currentcipherkeylabel)

### current cipher key textbox ###
$currentcipherkeyTextBox = New-Object System.Windows.Forms.MaskedTextBox 
$currentcipherkeyTextBox.Location = New-Object System.Drawing.Size($texbox_left,$height) 
$currentcipherkeyTextBox.AutoSize = $false
$currentcipherkeyTextBox.Size = New-Object System.Drawing.Size($textbox_size,23) 
$currentcipherkeyTextBox.PasswordChar = "*"
$Form.Controls.Add($currentcipherkeyTextBox)

### current cipher key tips label ###
$currentcipherkeytipslabel = New-Object System.Windows.Forms.Label
$currentcipherkeytipslabel.Location = New-Object System.Drawing.Size( ($texbox_left + $textbox_size),$height) 
$currentcipherkeytipslabel.Size = New-Object System.Drawing.Size(40,20) 
$currentcipherkeytipslabel.Text = "(*)"
$Form.Controls.Add($currentcipherkeytipslabel)

$height = $height + 30
### new cipher key label ###
$newcipherkeylabel = New-Object System.Windows.Forms.Label
$newcipherkeylabel.Location = New-Object System.Drawing.Size(20,$height) 
$newcipherkeylabel.Size = New-Object System.Drawing.Size($label_size,20) 
$newcipherkeylabel.Text = "new cipher key:"
$Form.Controls.Add($newcipherkeylabel)

### new cipher key textbox ###
$newcipherkeyTextBox = New-Object System.Windows.Forms.MaskedTextBox 
$newcipherkeyTextBox.Location = New-Object System.Drawing.Size($texbox_left,$height) 
$newcipherkeyTextBox.AutoSize = $false
$newcipherkeyTextBox.Size = New-Object System.Drawing.Size($textbox_size,23) 
$newcipherkeyTextBox.PasswordChar = "*"
$Form.Controls.Add($newcipherkeyTextBox)

$height = $height + 30
### cipher key algorithm label ###
$cipherkeyalgorithmlabel = New-Object System.Windows.Forms.Label
$cipherkeyalgorithmlabel.Location = New-Object System.Drawing.Size(20,$height) 
$cipherkeyalgorithmlabel.Size = New-Object System.Drawing.Size($label_size,20) 
$cipherkeyalgorithmlabel.Text = "new cipher key algorithm:"
$Form.Controls.Add($cipherkeyalgorithmlabel) 

### retype new current cipher key textbox ###
$cipherkeyalgorithmComboBox = New-Object System.Windows.Forms.ComboBox 
$cipherkeyalgorithmComboBox.Location = New-Object System.Drawing.Size($texbox_left,$height) 
$cipherkeyalgorithmComboBox.AutoSize = $false
$cipherkeyalgorithmComboBox.Size = New-Object System.Drawing.Size($textbox_size,23) 
$cipherkeyalgorithmComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cipherkeyalgorithmComboBox.Items.Add("aes")
$cipherkeyalgorithmComboBox.Items.Add("bf")
$cipherkeyalgorithmComboBox.SelectedIndex = 0
$Form.Controls.Add($cipherkeyalgorithmComboBox)

$height = $height + 30
### port label ###
$portlabel = New-Object System.Windows.Forms.Label
$portlabel.Location = New-Object System.Drawing.Size(20,$height) 
$portlabel.Size = New-Object System.Drawing.Size($label_size,20) 
$portlabel.Text = "Database Port Number:"
$Form.Controls.Add($portlabel) 

### port textbox ###
$portTextBox = New-Object System.Windows.Forms.TextBox
$portTextBox.Location = New-Object System.Drawing.Size($texbox_left,$height) 
$portTextBox.AutoSize = $false
$portTextBox.Size = New-Object System.Drawing.Size($textbox_size,23) 
$Form.Controls.Add($portTextBox)

$height = $height + 30
### DB name label ###
$dbnamelabel = New-Object System.Windows.Forms.Label
$dbnamelabel.Location = New-Object System.Drawing.Size(20,$height) 
$dbnamelabel.Size = New-Object System.Drawing.Size($label_size,20) 
$dbnamelabel.Text = "Database Name:"
$Form.Controls.Add($dbnamelabel) 

### DB name textbox ###
$dbnameTextBox = New-Object System.Windows.Forms.TextBox
$dbnameTextBox.Location = New-Object System.Drawing.Size($texbox_left,$height) 
$dbnameTextBox.AutoSize = $false
$dbnameTextBox.Size = New-Object System.Drawing.Size($textbox_size,23) 
$Form.Controls.Add($dbnameTextBox)

$height = $height + 30
### user name label ###
$usernamelabel = New-Object System.Windows.Forms.Label
$usernamelabel.Location = New-Object System.Drawing.Size(20,$height) 
$usernamelabel.Size = New-Object System.Drawing.Size($label_size,20) 
$usernamelabel.Text = "Database User Name:"
$Form.Controls.Add($usernamelabel) 

### user name textbox ###
$usernameTextBox = New-Object System.Windows.Forms.TextBox
$usernameTextBox.Location = New-Object System.Drawing.Size($texbox_left,$height) 
$usernameTextBox.AutoSize = $false
$usernameTextBox.Size = New-Object System.Drawing.Size($textbox_size,23) 
$Form.Controls.Add($usernameTextBox)

$height = $height + 30
### postgres access password label ###
$pgaccesslabel = New-Object System.Windows.Forms.Label
$pgaccesslabel.Location = New-Object System.Drawing.Size(20,$height) 
$pgaccesslabel.Size = New-Object System.Drawing.Size($label_size,20) 
$pgaccesslabel.Text = "Database User Password:"
$Form.Controls.Add($pgaccesslabel) 

### password textbox ###
$passwordTextBox = New-Object System.Windows.Forms.MaskedTextBox 
$passwordTextBox.Location = New-Object System.Drawing.Size($texbox_left,$height) 
$passwordTextBox.AutoSize = $false
$passwordTextBox.Size = New-Object System.Drawing.Size($textbox_size,23) 
$passwordTextBox.PasswordChar = "*"
$Form.Controls.Add($passwordTextBox)

$height = $height + 30
### postgresql install folder label ###
$pginstalllabel = New-Object System.Windows.Forms.Label
$pginstalllabel.Location = New-Object System.Drawing.Size(20,$height) 
$pginstalllabel.Size = New-Object System.Drawing.Size($label_size,20) 
$pginstalllabel.Text = "PostgreSQL Install Folder:"
$Form.Controls.Add($pginstalllabel) 

### postgresql install folder textbox ###
$pginstallTextBox = New-Object System.Windows.Forms.TextBox 
$pginstallTextBox.Location = New-Object System.Drawing.Size($texbox_left,$height) 
$pginstallTextBox.AutoSize = $false
$pginstallTextBox.Size = New-Object System.Drawing.Size($textbox_size,23) 
$Form.Controls.Add($pginstallTextBox)

### folderbrowser dialog ###
$fd = New-Object System.Windows.Forms.FolderBrowserDialog
$fd.Description = "Select PostgreSQL Install Folder"
$fd.ShowNewFolderButton = $false

### folderbrowser dialog button ###
$fdButton = New-Object System.Windows.Forms.Button
$fdButton.Location = New-Object System.Drawing.Size( ($texbox_left + $textbox_size) ,$height)
$fdButton.Size = New-Object System.Drawing.Size(23,23)
$fdButton.Text = "..."
$Form.Controls.Add($fdButton)

$height = $height + 40
### tips label1 ###
$tipslabel1 = New-Object System.Windows.Forms.Label
$tipslabel1.Location = New-Object System.Drawing.Size(20,$height) 
$tipslabel1.Size = New-Object System.Drawing.Size( ($label_size + $textbox_size) ,20) 
$tipslabel1.Text = "(*) : Don't need to enter for the first time."
$Form.Controls.Add($tipslabel1)

$button_left = $button_left + 100
### regist button ###
$registButton = New-Object System.Windows.Forms.Button
$registButton.Location = New-Object System.Drawing.Size($button_left,$button_height)
$registButton.Size = New-Object System.Drawing.Size(90,35)
$registButton.Text = "Key Regist"
$Form.Controls.Add($registButton)

$button_left = $button_left + 100
### exit button ###
$ExitButton = New-Object System.Windows.Forms.Button
$ExitButton.Location = New-Object System.Drawing.Size($button_left ,$button_height)
$ExitButton.Size = New-Object System.Drawing.Size(90,35)
$ExitButton.Text = "Exit"
$Form.Controls.Add($ExitButton)

$button_height = $button_height + 50
### Clear infor button ###
$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Location = New-Object System.Drawing.Size($button_left ,$button_height)
$clearButton.Size = New-Object System.Drawing.Size(70,30)
$clearButton.Text = "Clear"

######################################################
#			   clear input information			  #
######################################################
function clear_form {
	trap {
		$exmessage = $Error[0] | Out-String
		[System.Windows.Forms.MessageBox]::Show("$exmessage", "Internal error occurred", "OK", "Error", "button1")
		$Form.Close()
		return
	}

	$portTextBox.Text = ""
	$dbnameTextBox.Text = ""
	$usernameTextBox.Text = ""
	$passwordTextBox.Text = ""
	$pginstallTextBox.Text = ""
	$currentcipherkeyTextBox.Text = ""
	$newcipherkeyTextBox.Text = ""
	$cipherkeyalgorithmComboBox.SelectedIndex = 0
}
$clearButton.Add_Click({ clear_form })
$Form.Controls.Add($clearButton)

$Form.Topmost = $True

################ END MAIN FORM ################


########## MAIN ###########
## check Administrators ###
if (!(Test-IsAdmin)){ 
	[System.Windows.Forms.MessageBox]::Show("You must be Administrators to execute this action.","Not Administrator","OK","Error","button1")
	$Form.Close()
	return
}

#####################################################
#		   Connection Test Function				#
#####################################################
function connection_test{
	$con = & $env:PSQLCMD -w -t -A -c "select 1" 2>&1
	if($con -eq 1) {
	  	### check is super user ###
		$super=& $env:PSQLCMD -X -t -A -c "select usesuper from pg_user where usename='$env:PGUSER'"
	 	if ($super -ne "t"){
			[System.Windows.Forms.MessageBox]::Show("Must be superuser to execute this action.","Could not Connect","OK","Error","button1")
			return 1
		} 
	}
	else {
			[System.Windows.Forms.MessageBox]::Show("Could not connect to the database.","Could not Connect","OK","Error","button1")
			return 1
	}
}			

#####################################################
#			  CHECK template1 function			 #
#####################################################
function check_template1{
if($MyDB -ieq "template1") {
		[System.Windows.Forms.MessageBox]::Show("Could not use template1 database.","Could not use template1","OK","Error","button1")
		return 1
	}
}

#####################################################
#               CHECK FORM function                 #
#####################################################

### Check newcipherkey ####
function check_form_newcipherkey{
	if([string]::IsNullOrWhiteSpace($newcipherkeyTextBox.Text)) {
	[System.Windows.Forms.MessageBox]::Show("The length of new cipher key must not be zero.","Object length zero","OK","Error","button1")
	return 1
	}
}

### Check cipherkeyalgorithm ####
function check_form_cipherkeyalgorithm{
	if([string]::IsNullOrWhiteSpace($cipherkeyalgorithmComboBox.Text)) {
	[System.Windows.Forms.MessageBox]::Show("The length of new cipher key algorithm must not be zero.","Object length zero","OK","Error","button1")
	return 1
	}
}

### Check Port ####
function check_form_port{
	if([string]::IsNullOrWhiteSpace($portTextBox.Text)) {
		[System.Windows.Forms.MessageBox]::Show("The length of Port must not be zero.","Object length zero","OK","Error","button1")
		return 1
	} elseif(!($portTextBox.Text -match "^\d+$")) {
		[System.Windows.Forms.MessageBox]::Show("Port must be integer.","Port must be integer","OK","Error","button1")
		return 1
	}
}

### Check DB Name ####
function check_form_dbname{
	if([string]::IsNullOrWhiteSpace($dbnameTextBox.Text)) {
		[System.Windows.Forms.MessageBox]::Show("The length of Database must not be zero.","Object length zero","OK","Error","button1")
	return 1
	}
}

### Check SuperUser ####
function check_form_user{
	if([string]::IsNullOrWhiteSpace($usernameTextBox.Text)) {
	[System.Windows.Forms.MessageBox]::Show("The length of Superuser must not be zero.","Object length zero","OK","Error","button1")
	return 1
	}
}

### Check DB Password  ####
function check_form_dbpass{
	if([string]::IsNullOrWhiteSpace($passwordTextBox.Text)) {
	[System.Windows.Forms.MessageBox]::Show("The length of Database Password must not be zero.","Object length zero","OK","Error","button1")
	return 1
	}
}

### Check PostgreSQL Install Folder  ####
function check_form_pginsdir{
	if([string]::IsNullOrWhiteSpace($pginstallTextBox.Text)) {
	[System.Windows.Forms.MessageBox]::Show("The length of PostgreSQL Install Folder must not be zero.","Object length zero","OK","Error","button1")
	return 1
	}
}

#####################################################
#			   Confirmation function			    #
#####################################################

#### Validate #####
function confirmation_register{
	$msgBoxInput =  [System.Windows.Forms.MessageBox]::Show("Are you sure you want to register the cipher key?","Register confirm","YesNo","Question","button2")
		switch ($msgBoxInput) {
			'Yes' {
				return 0
				break
			}
			'No' {
				[System.Windows.Forms.MessageBox]::Show("Registering operation canceled.","Operation Canceled","OK","Information","button1")
				return 1
				break
			}
		}
}

##### Exit #####
function confirmation_exit{
	$msgBoxInput =  [System.Windows.Forms.MessageBox]::Show("Are you sure you want to exit?", "Exit confirm", "YesNo", "Question","button2")
		switch  ($msgBoxInput) {
			  'Yes' {
			   return 1
				break
			  }
			  'No' {
				return 0
				break
			  }
		}
}

##################	Push END   #####################

function Push_Exit {
	trap {
		$exmessage = $Error[0] | Out-String
		[System.Windows.Forms.MessageBox]::Show("$exmessage", "Internal error occurred", "OK", "Error", "button1")
		$Form.Close()
		return
	}

	$ret = confirmation_exit
	if($ret -eq 1){
		$Form.Close()
	}
}

$ExitButton.add_Click({ Push_Exit })


####################   Push Regist   ####################

function Push_Regist {
	trap {
		$exmessage = $Error[0] | Out-String
		[System.Windows.Forms.MessageBox]::Show("$exmessage", "Internal error occurred", "OK", "Error", "button1")
		$Form.Close()
		return
	}

	### register operation confirm ###
	$ret = confirmation_register
	if($ret -eq 1){
		return
	}
	####################################

	### CHECK input connection parameter for psql ###
	$ret = check_form_newcipherkey
	if($ret -eq 1){
		return
	}

	$ret = check_form_cipherkeyalgorithm
	if($ret -eq 1){
		return
	}

	$ret = check_form_port
	if($ret -eq 1){
		return
	}

	$ret = check_form_dbname
	if($ret -eq 1){
		return
	}

	$ret = check_form_user
	if($ret -eq 1){
		return
	}

	$ret = check_form_dbpass
	if($ret -eq 1){
		return
	}

	$ret = check_form_pginsdir
	if($ret -eq 1){
		return
	}

	###   Setting form information   ####
	$CurrentKey = $currentcipherkeyTextBox.Text
	$NewKey = $newcipherkeyTextBox.Text
	$KeyAlgorithm = $cipherkeyalgorithmComboBox.Text
	$MyPort  = $portTextBox.Text
	$MyDB = $dbnameTextBox.Text
	$MyUid = $usernameTextBox.Text
	$MyPass = $passwordTextBox.Text
	$PGPATH = $pginstallTextBox.Text
	$env:PGPORT = "$MyPort"
	$env:PGDATABASE = "$MyDB"
	$env:SuperU = "$MyUid"
	$env:SuperP = "$MyPass"
	$env:PGUSER = $env:SuperU
	$env:PGPASSWORD = $env:SuperP
	$LIBPQ= Join-Path $PGPATH "bin\libpq.dll"
	$env:PSQLCMD = Join-Path $PGPATH "bin\psql.exe"
	####################################

	if (!(Test-Path $env:PSQLCMD)) {
		[System.Windows.Forms.MessageBox]::Show("psql file does not exist. File name: $env:PSQLCMD `nHINT:  Check the PostgreSQL Install Folder, and Try again","psql file not exist","OK","Error","button1")
		return
	}

	if (!(Test-Path $LIBPQ)) {
		[System.Windows.Forms.MessageBox]::Show("dll file does not exist. File name: $LIBPQ `nHINT:  Check the PostgreSQL Install Folder, and Try again","dll file not exist","OK","Error","button1")
		return
	}

	#check DB if = template1
	$ret = check_template1
	if($ret -eq 1){
		return
	}
	
	#################################################

	##### connection test #####
	$ret = connection_test
	if($ret -eq 1){
		return
	}
	###########################

	# Change display of form
	$GenaralLabel.Text = "Registering..."

	$global:LASTEXITCODE = 0
	$filename = Get-Date -Format "yyyyMMdd-HHmmss"
    $env:ERRFILE = $env:tdeforpgroot + "bin\error_" + $filename
	"select cipher_key_disable_log();
	select cipher_key_regist('$CurrentKey', '$NewKey','$KeyAlgorithm');
	select cipher_key_enable_log();" | & $env:PSQLCMD --set ON_ERROR_STOP=ON -1 2>$env:ERRFILE 1>$env:null

	if($global:LASTEXITCODE -ne 0) {
		$GenaralLabel.Text = "Please enter the information to the following fields:"
		[System.Windows.Forms.MessageBox]::Show("Could not register cipher key.`nHINT : Please see $env:ERRFILE for detail.","Register Failed","OK","Error","button1")
		return
	}
	# remove error log file if register OK.
	Remove-Item $env:ERRFILE

	[System.Windows.Forms.MessageBox]::Show("cipher key registered!","Register success!","OK","Information","button1")
	$GenaralLabel.Text = "Please enter the information to the following fields:"
}

$registButton.add_Click({ Push_Regist })

####################   Push FolderDialog   ####################

function Push_FolderDialog {
	trap {
		$exmessage = $Error[0] | Out-String
		[System.Windows.Forms.MessageBox]::Show("$exmessage", "Internal error occurred", "OK", "Error", "button1")
		$Form.Close()
		return
	}

	if($fd.ShowDialog($Form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $pginstallTextBox.Text = $fd.SelectedPath
    }
}

$fdButton.add_Click({ Push_FolderDialog })

$Form.Add_Shown({$Form.Activate()})
$Form.ShowDialog() | out-null
