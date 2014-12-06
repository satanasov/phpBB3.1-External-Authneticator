#!/usr/bin/php
<?php
/**
* @ignore
*/
define('IN_PHPBB', true);
$phpbb_root_path = '/some/path/that/phpbb/is/installed';
$phpEx = substr(strrchr(__FILE__, '.'), 1);
include($phpbb_root_path . 'common.' . $phpEx);
// Start session management
class JabberAuth {
	var $debug 		= true; 				      /* Debug mode */
	var $debugfile 	= "/opt/ejabberd/pipe-debug.log";  /* Debug output */
	var $logging 	= true; 				      /* Do we log requests ? */
	var $logfile 	= "/opt/ejabberd/pipe-log.log" ;   /* Log file ... */
	/*
	 * For both debug and logging, ejabberd have to be able to write.
	 */

	var $jabber_user;   /* This is the jabber user passed to the script. filled by $this->command() */
	var $jabber_pass;   /* This is the jabber user password passed to the script. filled by $this->command() */
	var $jabber_server; /* This is the jabber server passed to the script. filled by $this->command(). Useful for VirtualHosts */
	var $jid;           /* Simply the JID, if you need it, you have to fill. */
	var $data;          /* This is what SM component send to us. */

	var $dateformat = "M d H:i:s"; /* Check date() for string format. */
	var $command; /* This is the command sent ... */
	var $mysock;  /* MySQL connection ressource */
	var $stdin;   /* stdin file pointer */
	var $stdout;  /* stdout file pointer */

	function JabberAuth()
	{
		@openlog("pipe-auth", LOG_NDELAY, LOG_SYSLOG);

		if($this->debug) {
			@error_reporting(E_ALL);
			@ini_set("log_errors", "1");
			@ini_set("error_log", $this->debugfile);
		}
		$this->logg("Starting pipe-auth ..."); // We notice that it's starting ...
		$this->openstd();
	}

	function stop()
	{
		$this->logg("Shutting down ..."); // Sorry, have to go ...
		closelog();
		$this->closestd(); // Simply close files
		exit(0); // and exit cleanly
	}

	function openstd()
	{
		$this->stdout = @fopen("php://stdout", "w"); // We open STDOUT so we can read
		$this->stdin  = @fopen("php://stdin", "r"); // and STDIN so we can talk !
	}

	function readstdin()
	{
		$l      = @fgets($this->stdin, 3); // We take the length of string
		$length = @unpack("n", $l); // ejabberd give us something to play with ...
		$len    = $length["1"]; // and we now know how long to read.
		if($len > 0) { // if not, we'll fill logfile ... and disk full is just funny once
			$this->logg("Reading $len bytes ... "); // We notice ...
			$data   = @fgets($this->stdin, $len+1);
			// $data = iconv("UTF-8", "ISO-8859-15", $data); // To be tested, not sure if still needed.
			$this->data = $data; // We set what we got.
			$this->logg("IN: ".$data);
		}
	}

	function closestd()
	{
		@fclose($this->stdin); // We close everything ...
		@fclose($this->stdout);
	}

	function out($message)
	{
		@fwrite($this->stdout, $message); // We reply ...
		$dump = @unpack("nn", $message);
		$dump = $dump["n"];
		$this->logg("OUT: ". $dump);
	}

	function play()
	{
		do {
			
			$this->readstdin(); // get data
			$length = strlen($this->data); // compute data length
			if($length > 0 ) { // for debug mainly ...
				$this->logg("GO: ".$this->data);
				$this->logg("data length is : ".$length);
			}
			//$this->logg($this->data);
			$ret = $this->command(); // play with data !
			$this->logg("RE: " . $ret); // this is what WE send.
			$this->out($ret); // send what we reply.
			$this->data = NULL; // more clean. ...
		} while (true);
	}

	function logg($message) // pretty simple, using syslog.
	// some says it doesn't work ? perhaps, but AFAIR, it was working.
	{
		if($this->logging) {
			@syslog(LOG_INFO, $message);
		}
	}

	function command()
	{
		//$data = $this->splitcomm(); // This is an array, where each node is part of what SM sent to us :
		$pred = explode(":", $this->data);
		//log("Command executed");
		// 0 => the command,
		// and the others are arguments .. e.g. : user, server, password ...
		$this->logg($pred[0]);
		//echo "test";
		if(strlen($pred[0]) > 0 ) {
			//echo "Command was : ".$data[0];
		}
		switch($pred[0]) {
			case "isuser": // this is the "isuser" command, used to check for user existance
				echo 'here be dragons';
				$this->jabber_user = $pred[1];
				$parms = $pred[1];  // only for logging purpose
				$return = $this->checkuser();
			break;
					
			case "auth": // check login, password
						
				$this->jabber_user = $pred[1];
				$this->jabber_pass = $pred[3];
				$parms = $pred[1].":".$pred[2]; // only for logging purpose
				$return = $this->checkpass();
			break;
					
			case "setpass":
				$return = false; // We do not want jabber to be able to change password
			break;
					
			default:
				$this->stop(); // if it's not something known, we have to leave.
				// never had a problem with this using ejabberd, but might lead to problem ?
			break;
		}
		
		$return = ($return) ? 1 : 0;
	}

	function login($username, $password, $autologin = false, $viewonline = 1, $admin = 0)
	{
		global $db, $user, $phpbb_root_path, $phpEx, $phpbb_container, $auth, $user, $config;
		$provider_collection = $phpbb_container->get('auth.provider_collection');
		$provider = $provider_collection->get_provider();
		if ($provider)
		{
			$login = $provider->login($username, $password);
		}
		$this->logg($login['status']);
		if ($login['status'] == 3)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	function checkpass()
	{
		global $phpbb_container, $auth, $user, $config, $db;
		$this->logg("Checkpass");
		$this->logg($this->jabber_user);
		$user_decode = str_replace('\20', ' ', $this->jabber_user);
		$this->logg($user_decode);
		$jabber_user_clean = utf8_clean_string($user_decode);
		$this->logg($jabber_user_clean);
		$sql = 'SELECT * FROM phpbb_users WHERE username_clean = \''.$jabber_user_clean.'\'';
		$this->logg("SQL:".$sql);
		$result = $db->sql_query($sql);
		$row = $db->sql_fetchrow($result);
		$db->sql_freeresult($result);
		$this->logg("DB PASS:".$row['user_password']);
		$jabber_pass_md5 = md5($this->jabber_pass);
		$this->logg("JABBER PASS: ". $this->jabber_pass);
		$checker = false;
		$this->logg($this->login($this->jabber_user, $this->jabber_pass));
		if($this->login($this->jabber_user, $this->jabber_pass) AND $row['user_inactive_reason'] == 0) {
			$checker = true;
		} 
		else {
			$this->logg("Secondary Check to SESSION DB");
			$sql1 = 'SELECT session_id FROM phpbb_sessions WHERE session_user_id = '.$row['user_id'];
			$this->logg($sql1);
			$result = $db->sql_query($sql1);
			$row1 = $db->sql_fetchrow($result);
			$db->sql_freeresult($result);
			$this->logg($row1['session_id']);
			if ($this->jabber_pass == $row1['session_id'] AND $row['user_inactive_reason'] == 0) {
				$checker = true;
			}
		}
		if ($checker)
		{
			$sql2 = 'SELECT ban_id FROM phpbb_banlist WHERE ban_id = '.$row['user_id'];
			$this->logg($sql2);
			$result = $db->sql_query($sql2);
			$row2 = (int) $db->sql_fetchfield('ban_id');
			$db->sql_freeresult($result);
			if ($row2['ban_id'] != 0)
			{
				$checker = false;
			}
		}
		$this->logg($checker);
		return $checker;
	}
}

$auth = new JabberAuth();
$auth->play(); // We simply start process !
?>