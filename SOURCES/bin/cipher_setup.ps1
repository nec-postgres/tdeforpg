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

function error_exit([string] $action) {
	$exmessage = $Error[0] | Out-String
	[System.Windows.Forms.MessageBox]::Show("$exmessage", "Internal error occurred", "OK", "Error", "button1")

	switch  ($action.ToLower()) {
		'validate' {
			if (Test-Path $env:INSTALLFILE) {
				Remove-Item $env:INSTALLFILE 2>&1 1>$null
			}
			break
		}
		'invalidate' {
			if (Test-Path $env:INSTALLFILE) {
				Set-Content $env:INSTALLFILE ""
			}
			break
		}
	}
	$Form.Close()

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
$env:KEYTBL="cipher_key_table"
$env:KEYMGTTBL="key_management_table"
$env:NOKEYTBL="cipher_key_table_uninst"
$env:tdeforpgroot = $PSScriptRoot | %{$_ -replace "bin",""} 
$env:SCRPATH=$env:tdeforpgroot+"lib\init\"
$env:TDE_CURR_NUM_VERSION="1.2.1"
$env:TDE_CURR_VERSION="Free Edition "+ $env:TDE_CURR_NUM_VERSION + ".0"
$env:FILE=$env:SCRPATH

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
$Form.Text = "NEC TDE for PG Free Edition V" + $env:TDE_CURR_NUM_VERSION + " Cipher Setup"
$Form.Size = New-Object System.Drawing.Size(520,350) 
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

$height = $height + 30
### Validate button ###
$validateButton = New-Object System.Windows.Forms.Button
$validateButton.Location = New-Object System.Drawing.Size($button_left,$button_height)
$validateButton.Size = New-Object System.Drawing.Size(90,35)
$validateButton.Text = "Activate TDE Feature"
$Form.Controls.Add($validateButton)

$button_left = $button_left + 100
### Invalidate button ###
$invalidateButton = New-Object System.Windows.Forms.Button
$invalidateButton.Location = New-Object System.Drawing.Size($button_left,$button_height)
$invalidateButton.Size = New-Object System.Drawing.Size(90,35)
$invalidateButton.Text = "Inactivate TDE Feature"
$Form.Controls.Add($invalidateButton)

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
#		   File Exist Test Function				#
#####################################################
function file_exist_check{
	if (!(Test-Path $env:FILE)) {
		[System.Windows.Forms.MessageBox]::Show("File does not exist: $env:FILE","Not Exist file","OK","Error","button1")
		initialize
		$Form.Close()
		return 1
	}
}	

#####################################################
#      Check existing of KEYTBL table function      #
#####################################################
function cipherkeytbl_exist_check{
	$env:KEYTBL_EXIST=& $env:PSQLCMD -X -t -A -c "SELECT COUNT(*) FROM PG_TABLES WHERE TABLENAME='$env:KEYTBL'"
	if (($env:KEYTBL_EXIST) -ne 0) {
		return 1 
	} else {
		return 0
	}
}	

#####################################################
#      Check existing of NOKEYTBL table function    #
#####################################################
function cipherkeyuninsttbl_exist_check{
	$env:KEYTBL_EXIST=& $env:PSQLCMD -X -t -A -c "SELECT COUNT(*) FROM PG_TABLES WHERE TABLENAME='$env:NOKEYTBL'"
	if (($env:KEYTBL_EXIST) -ne 0) {
		return 1 
	} else {
		return 0
	}
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
#        Setting permission to install file         #
#####################################################
function set_permission_to_file{
	echo Y | CACLS $env:PERMISSIONSETFILE /G Administrators:F
}

#####################################################
#           insert parallel setting file            #
#####################################################
function insert_parallel_setting_file{
	$env:event="insert_parallel_setting_file"
	# IndexOF return -1 if not exist
	if($env:tdeforpgroot.ToLower().IndexOF("tdeforpg95") -eq -1) {
		$env:FILE=$env:SCRPATH+"pgtde_parallel_safe_setting.sql"
		$ret = plus_installfile
		if ($ret -eq 1) {
			return 1
		}
		return 0
	}
}

#####################################################
# Plus contents of file to INSTALLFILE function     #
#####################################################
function plus_installfile{
	$sql = Get-Content $env:FILE
	if ($? -eq 0) {
		return 1
	}
	Add-content $env:INSTALLFILE $sql
	if ($? -eq 0) {
		return 1
	}
}

#####################################################
#                 clean misc thing                  #
#####################################################
function initialize{
	if (Test-Path $env:INSTALLFILE) {
		Remove-Item $env:INSTALLFILE 2>&1 1>$null
	}
	$env:INSTALLFILE=$env:tdeforpgroot
	$env:FILE=$env:SCRPATH
	$GenaralLabel.Text = "Please enter the information to the following fields:"
}

#####################################################
#               CHECK FORM function                 #
#####################################################

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
function confirmation_validate{
	$msgBoxInput =  [System.Windows.Forms.MessageBox]::Show("Are you sure you want to activate the transparent data encryption feature?","Activate confirm","YesNo","Question","button2")
		switch ($msgBoxInput) {
			'Yes' {
				return 0
				break
			}
			'No' {
				[System.Windows.Forms.MessageBox]::Show("Activating operation canceled.","Operation Canceled","OK","Information","button1")
				return 1
				break
			}
		}
}

##### Invalidate #####
function confirmation_invalidate{
	$msgBoxInput =  [System.Windows.Forms.MessageBox]::Show("Are you sure you want to inactivate the transparent data encryption feature?`nEncrypted data will NOT be able to access until reactivate.","Inactivate confirm","YesNo","Question","button2")
		switch  ($msgBoxInput) {
			'Yes' {
				return 0
				break
			}
			'No' {
				[System.Windows.Forms.MessageBox]::Show("Inactivating operation canceled.","Operation Canceled","OK","Information","button1")
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


####################   Push Invalidate   ####################

function Push_Invalidate {
	trap {
		$exmessage = $Error[0] | Out-String
		[System.Windows.Forms.MessageBox]::Show("$exmessage", "Internal error occurred", "OK", "Error", "button1")

		$env:INSTALLFILE = $env:tdeforpgroot+"\sys\$env:PGDATABASE.cipher.inst"
		if (Test-Path $env:INSTALLFILE) {
			Set-Content $env:INSTALLFILE ""
		}
		$Form.Close()
		return
	}

	### Invalidating operation confirm ###
	$ret = confirmation_invalidate
	if($ret -eq 1){
		return
	}
	######################################
	
	#################################################
	### CHECK input connection parameter for psql ###
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
	######################################

	if (!(Test-Path $env:PSQLCMD)) {
		[System.Windows.Forms.MessageBox]::Show("psql file does not exist. File name: $env:PSQLCMD `nHINT:  Check the PostgreSQL Install Folder, and Try again","psql file not exist","OK","Error","button1")
		return
	}

	if (!(Test-Path $LIBPQ)) {
		[System.Windows.Forms.MessageBox]::Show("dll file does not exist. File name: $LIBPQ `nHINT:  Check the PostgreSQL Install Folder, and Try again","dll file not exist","OK","Error","button1")
		return
	}

	##### connection test #####
	$ret = connection_test
	if($ret -eq 1){
		return
	}
	###########################

	# Change display of form
	$GenaralLabel.Text = "Inactivating..."

	# check if already inactivated
	$ret = cipherkeytbl_exist_check
	if($ret -eq 0){
		[System.Windows.Forms.MessageBox]::Show("Transparent data encryption feature has not been activated yet.","Not yet activated","OK","Warning","button1")
		$env:INSTALLFILE=$env:tdeforpgroot
		$env:FILE=$env:SCRPATH
		$GenaralLabel.Text = "Please enter the information to the following fields:"
		return
	}
	############################
	
	# check lock file, error if not exist
	$env:INSTALLFILE = $env:tdeforpgroot+"\sys\$env:PGDATABASE.cipher.inst"
	if (!(Test-Path $env:INSTALLFILE)) {
		[System.Windows.Forms.MessageBox]::Show("Lock file does not exist. File name: $env:INSTALLFILE `nHINT:  Check the Lock file, and Try again","Lock file not exist","OK","Error","button1")
		$Form.Close()
		return
	}
	############################
	
	# init inactivate file
	Add-Content $env:INSTALLFILE "SET search_path TO public;" -Encoding UTF8
	if ($? -eq 0) {
		error_exit "invalidate"
		return
	}
	
	#setting permission to install file
	$env:PERMISSIONSETFILE=$env:INSTALLFILE
	set_permission_to_file
	############################
	
	#### Add invalidation sql script ###
$str = @"
DROP FUNCTION IF EXISTS PGTDE_BEGIN_SESSION(TEXT,TEXT,TEXT);
DROP FUNCTION IF EXISTS PGTDE_BEGIN_SESSION(TEXT);
DROP FUNCTION IF EXISTS PGTDE_END_SESSION();
ALTER TABLE `"${env:KEYTBL}`" RENAME TO `"${env:NOKEYTBL}`";
"@
	Add-content $env:INSTALLFILE $str
	if ($? -eq 0) {
		error_exit "invalidate"
		return
	}
	##########################################
	
	$global:LASTEXITCODE = 0
	$filename = Get-Date -Format "yyyyMMdd-HHmmss"
	$env:ERRFILE = $env:tdeforpgroot + "bin\error_" + $filename
	& $env:PSQLCMD --set ON_ERROR_STOP=ON -1 -f $env:INSTALLFILE 2>$env:ERRFILE 1>$env:null
	if($global:LASTEXITCODE -ne 0) {
		Set-Content $env:INSTALLFILE ""
		$env:INSTALLFILE=$env:tdeforpgroot
		$env:FILE=$env:SCRPATH
		$GenaralLabel.Text = "Please enter the information to the following fields:"
		[System.Windows.Forms.MessageBox]::Show("Could not inactivate  transparent data encryption feature.`nHINT : Please see $env:ERRFILE for detail.","Inactivate Failed","OK","Error","button1")
		return
	}

	# remove error log file if inactivate OK.
	Remove-Item $env:ERRFILE

	Remove-Item $env:INSTALLFILE 2>&1 1>$null
	$GenaralLabel.Text = "Please enter the information to the following fields:"
	[System.Windows.Forms.MessageBox]::Show("The transparent data encryption feature has been inactivated.","Inactivate success!","OK","Information","button1")
}

$invalidateButton.add_Click({ Push_Invalidate })


####################   Push Validate   ####################

function Push_Validate {
	trap {
		$exmessage = $Error[0] | Out-String
		[System.Windows.Forms.MessageBox]::Show("$exmessage", "Internal error occurred", "OK", "Error", "button1")
		$env:INSTALLFILE = $env:tdeforpgroot+"\sys\$env:PGDATABASE.cipher.inst"
		if (Test-Path $env:INSTALLFILE) {
			Remove-Item $env:INSTALLFILE 2>&1 1>$null
		}
		$Form.Close()
		return
	}

	### Validating operation confirm ###
	$ret = confirmation_validate
	if($ret -eq 1){
		return
	}
	####################################

	### CHECK input connection parameter for psql ###
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
	$GenaralLabel.Text = "Activating..."

	# check if already activated
	$ret = cipherkeytbl_exist_check
	if($ret -eq 1){
		[System.Windows.Forms.MessageBox]::Show("Transparent data encryption function has already been activated.","TDE already been activated","OK","Warning","button1")
		$env:INSTALLFILE=$env:tdeforpgroot
		$env:FILE=$env:SCRPATH
		$GenaralLabel.Text = "Please enter the information to the following fields:"
		return
	}
	############################

	# check lock file, error if already exist
	$env:INSTALLFILE = $env:tdeforpgroot+"\sys\$env:PGDATABASE.cipher.inst"
	if (Test-Path $env:INSTALLFILE) {
		[System.Windows.Forms.MessageBox]::Show("Lock file already exists. File name: $env:INSTALLFILE `nHINT:  Remove the Lock file, and Try again","Lock file exists","OK","Error","button1")
		$Form.Close()
		return
	}
	############################


	### create install file ####
	Add-Content $env:INSTALLFILE "SET search_path TO public;" -Encoding UTF8
	if ($? -eq 0) {
		error_exit "validate"
		return
	}
	############################
	
	#setting permission to install file
	$env:PERMISSIONSETFILE=$env:INSTALLFILE
	set_permission_to_file
	############################
	
	# check for re-activate
	$ret = cipherkeyuninsttbl_exist_check
	# Activate
	if($ret -eq 0){
	
		# file exist check
		$env:FILE=$env:SCRPATH+"cipher_definition.sql"
		$ret = file_exist_check
		if ($ret -eq 1) {
			return
		}
		$env:FILE=$env:SCRPATH+"cipher_key_function.sql"
		$ret = file_exist_check
		if ($ret -eq 1) {
			return
		}
		$env:FILE=$env:SCRPATH+"common_session_create.sql"
		$ret = file_exist_check
		if ($ret -eq 1) {
			return
		}
		##########################################
		
		# add content of file to INSTALLFILE
		$env:FILE=$env:SCRPATH+"cipher_definition.sql"
		$ret = plus_installfile
		if ($ret -eq 1) {
			error_exit "validate"
			return
		}
		$env:FILE=$env:SCRPATH+"cipher_key_function.sql"
		$ret = plus_installfile
		if ($ret -eq 1) {
			error_exit "validate"
			return
		}
		$env:FILE=$env:SCRPATH+"common_session_create.sql"
		$ret = plus_installfile
		if ($ret -eq 1) {
			error_exit "validate"
			return
		}
		##########################################
	}
	# re-activate
	else
	{
		# Rename cipher_key_table_uninst to cipher_key_table
		Add-Content $env:INSTALLFILE "ALTER TABLE $env:NOKEYTBL RENAME TO $env:KEYTBL;" -Encoding UTF8

		# file exist check
		$env:FILE=$env:SCRPATH+"cipher_key_function.sql"
		$ret = file_exist_check
		if ($ret -eq 1) {
			return
		}
		$env:FILE=$env:SCRPATH+"common_session_create.sql"
		$ret = file_exist_check
		if ($ret -eq 1) {
			return
		}
		
		# put into install file
		$env:FILE=$env:SCRPATH+"cipher_key_function.sql"
		$ret = plus_installfile
		if ($ret -eq 1) {
			error_exit "validate"
			return
		}
		$env:FILE=$env:SCRPATH+"common_session_create.sql"
		$ret = plus_installfile
		if ($ret -eq 1) {
			error_exit "validate"
			return
		}
	}

	# grant public access to cipher_key_table and key_management_table
	Add-Content $env:INSTALLFILE "GRANT SELECT ON $env:KEYTBL TO PUBLIC;" -Encoding UTF8
	if ($? -eq 0) {
		error_exit "validate"
		return
	}

	##########################################

	#CHECK PostgreSQL Version and put parallel setting file.
	$ret = insert_parallel_setting_file
	if ($ret -eq 1) {
		error_exit "validate"
		return
	}

	##########################################

	$global:LASTEXITCODE = 0
	$filename = Get-Date -Format "yyyyMMdd-HHmmss"
	$env:ERRFILE = $env:tdeforpgroot + "bin\error_" + $filename
	& $env:PSQLCMD --set ON_ERROR_STOP=ON -1 -f $env:INSTALLFILE 2>$env:ERRFILE 1>$env:null
	if($global:LASTEXITCODE -ne 0) {
		initialize
		[System.Windows.Forms.MessageBox]::Show("Could not activate transparent data encryption feature.`nHINT : Please see $env:ERRFILE for detail.","Activate failed","OK","Error","button1")
		return
	}
	# remove error log file if activate OK.
	Remove-Item $env:ERRFILE

	# empty INSTALLFILE
	Set-Content $env:INSTALLFILE ""
	
	[System.Windows.Forms.MessageBox]::Show("Transparent data encryption feature has been activated!","Activate success!","OK","Information","button1")
	$GenaralLabel.Text = "Please enter the information to the following fields:"
}

$validateButton.add_Click({ Push_Validate })

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
