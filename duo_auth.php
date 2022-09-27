<?php
/**
 * Two Factor Authentication using Duo Security for RoundCube
 *
 * @version 1.0.7
 *
 * Author(s): Alexios Polychronopoulos <dev@pushret.co.uk>
 * Author(s): Leonardo Marino-Ramirez <marino@marino-johnson.org>
 * Author(s): Johnson Chow <wschow@Comp.HKBU.Edu.HK>
 * Date: 01/30/2021
 */


require_once 'duo_web.php';
require_once 'Client.php';
require_once 'Auth.php';
require_once 'Requester.php';
require_once 'CurlRequester.php';
use Duo\DuoUniversal\Client;
use Duo\DuoUniversal\DuoException;

class duo_auth extends rcube_plugin 
{

	function init() 
	{
		$rcmail = rcmail::get_instance();
		
		$this->add_hook('login_after', array($this, 'login_after'));
		$this->add_hook('send_page', array($this, 'check_2FA'));
   	    	 
		$this->load_config();
	}

	//hook called after successful user/pass authentication.
	function login_after($args)
	{
		$rcmail = rcmail::get_instance();
		
		$this->register_handler('plugin.body', array($this, 'generate_html'));
		
		$ikey = $this->get('IKEY');
		$skey = $this->get('SKEY');
        $host = $this->get('HOST');
        $redirect = $this->get('REDIRECT');
        $user = trim(rcube_utils::get_input_value('_user', rcube_utils::INPUT_POST, true));

        try {
            $duo_client = new Client(
                $ikey,
                $skey,
                $host,
                $redirect
            );
        } catch (DuoException $e) {
            throw new ErrorException("*** Duo config error. Verify the values in the duo config are correct ***\n" . $e->getMessage());
        }

		// bypass local users
		if(in_array($user, $this->get('2FA_OVERRIDE_USERS'))) {
            $_SESSION['_Duo_2FAuth'] = True;
            header('Location: ?_task=mail');
        }


		// 2FA override with specific IPs 
		foreach($this->get('2FA_OVERRIDE') as $ip) {
			if($this->ipCIDRCheck($_SERVER['REMOTE_ADDR'],$ip)) {
				$_SESSION['_Duo_2FAuth'] = True;
				header('Location: ?_task=mail');
			}
		}

		//indicates that user/pass authentication has succeeded.
		$_SESSION['_Duo_Auth'] = True;
    	
		$rcmail->output->send('plugin');
	}
    
	//hook called on every roundcube page request. Makes sure that user is authenticated using 2 factors.
	function check_2FA($p)
	{
		$rcmail = rcmail::get_instance();
		
		//user has gone through 2FA
		if($_SESSION['_Duo_Auth'] && $_SESSION['_Duo_2FAuth']) 
		{
			return $p;
		}
		
		//login page has to allow requests that are not 2 factor authenticated.
		else if($rcmail->task == 'login')
		{
			return $p;
		}
		
		//checking 2nd factor of authentication.
		else if(isset($_POST['sig_response']))
		{
            $ikey = $this->get('IKEY');
            $skey = $this->get('SKEY');
            $host = $this->get('HOST');
            $redirect = $this->get('REDIRECT');
            $username = trim(rcube_utils::get_input_value('_user', rcube_utils::INPUT_POST, true));

            try {
                $duo_client = new Client(
                    $ikey,
                    $skey,
                    $host,
                    $redirect
                );
            } catch (DuoException $e) {
                throw new ErrorException("*** Duo config error. Verify the values in the duo config are correct ***\n" . $e->getMessage());
            }

            $state = $duo_client->generateState();
            $_SESSION['state'] = $state;
            $_SESSION['username'] = $username;

            # Redirect to prompt URI which will redirect to the client's redirect URI after 2FA
            $prompt_uri = $duo_client->createAuthUrl($username, $state);
            $resp = url(prompt_uri)
			
			//successful 2FA login.
			if($resp != NULL)
			{
				//indicates successful Duo 2FA.
				$_SESSION['_Duo_2FAuth'] = True;
				
				//redirect to inbox.
				header('Location: ?_task=mail');
				return $p;
			}
			else {
				$this->fail();
			}
		}
		
		//in any other case, log the user out.
		$this->fail();
	}

	private function get($v)
	{
		return rcmail::get_instance()->config->get($v);
	}
	
	//unsets all the session variables used in the plugin, 
	//invalidates the user's session and redirects to the login page.
	private function fail() 
	{
		$rcmail = rcmail::get_instance();
		
		unset($_SESSION['_Duo_Auth']);
		unset($_SESSION['_Duo_2FAuth']);
		
		$rcmail->kill_session();
		header('Location: ?_task=login');
		
		exit;
	}	
	
	private function ipCIDRCheck ($IP, $CIDR) {
		if (!preg_match('/\//',$CIDR)) { $CIDR=$CIDR . "/32"; }

		list ($net, $mask) = explode ('/', $CIDR);
		$ip_net = ip2long ($net);
		$ip_mask = ~((1 << (32 - $mask)) - 1);
    		$ip_ip = ip2long ($IP);
    		return (($ip_ip & $ip_mask) == ($ip_net & $ip_mask));
	}
}
