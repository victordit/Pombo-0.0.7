<?php /* Pombo 0.0.7 */
$PASSWORD='yourpassword';
if (isset($_POST['myip'])) { die($_SERVER['REMOTE_ADDR']); }
if ($_POST['token']!=hash_hmac('sha1',$_POST['filedata'].'***'.$_POST['filename'],$PASSWORD)) { die('Wrong password'); }
if (pathinfo($_POST['filename'],PATHINFO_EXTENSION)!='gpg') { die('Not a gpg file.'); }
if (!preg_match('/^[a-zA-Z0-9\.\-\_]*$/', $_POST['filename'])) { die('Invalid characters in filename.'); }
$fh = fopen($_POST['filename'],'xb'); if (!$fh) die('Could not write file.');
if (!fwrite($fh,base64_decode($_POST['filedata'])))  { die('Could not write file.'); }

if(isset($_POST['email'])){
	$message = "Hi pombiano, Pombo has send a new report from ip ".$_POST['myip']."\n";
	$message .= "Check your server \n";
	// Send
	if(mail($_POST['email'], 'Send Pombo Report from Ip '.$_POST['myip'], $message)){
		fclose($fh); echo "File stored and send email.";
	}else{
		fclose($fh); echo "File stored but can't send email.";
	}
	
	exit;
}

fclose($fh); echo "File stored.";
?>
