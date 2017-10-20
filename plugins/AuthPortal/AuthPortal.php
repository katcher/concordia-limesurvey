<?php
class AuthPortal extends AuthPluginBase {

    protected $storage = 'DbStorage';
    static protected $description = 'Portal Token authentication';
    static protected $name = 'Concordia University Reverse Authentication';
    
    public function init() {
    
    	/**
    	 * Here you should handle subscribing to the events your plugin will handle
    	 */
    	
		$this->subscribe('beforeLogin');    	
    	$this->subscribe('newUserSession');
    	
    }
    public function beforeLogin() { 

    	$request = $this->api->getRequest();    	
    	if (!is_null($request->getParam('token')) and !is_null($request->getParam('dbname'))) {
    		$token = $request->getParam('token');
    		$dbname = $request->getParam('dbname');
    		
    		function Concordia_Send_To_Host ( $token, $dbname, $lang = "ENG" ){
    			$url = "https://psis.concordia.ca/CUPORTAL/services/wsPortalAuth.asp?";
    			$tmp = ''; $error = (string) null; $msg = ''; $errno = '';
    			if(!$lang) {
    				$lang = 'ENG';
    			}
    			$url .= 'token='. urlencode($token) . '&dbname=' . urlencode($dbname);
    			$options = array();
    			$options = array(
    					CURLOPT_URL => $url,
    					CURLOPT_SSL_VERIFYHOST => 0,
    					CURLOPT_SSL_VERIFYPEER => false,
    					CURLOPT_HEADER => 0,
    					CURLOPT_RETURNTRANSFER => true,
    					CURLOPT_CONNECTTIMEOUT => 5,
    					CURLOPT_TIMEOUT        => 5,
    			);
    			$ch = curl_init();
    			curl_setopt_array($ch, $options);
    			$resultstr = curl_exec($ch);
    			 
    			$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    			$errno .= "\n[".curl_errno($ch)."]\n";
    			$msg .= print_r(curl_getinfo($ch),true );
    			$msg .= $errno;
    			curl_close($ch);
    			if( $http_code == 200 ) {
    				return $resultstr;
    			}
    			$resultstr = "\n" .
    					'<?xml version="1.0" standalone="yes"?>' . "\n" .
    					'<authentication>' . "\n" .
    					'<!-- token='.$token.'&dbname='.$dbname.'&language='.$lang.' -->' . "\n" .
    					'<portalauth authenticated="false">Connection Error.'.$errno.'</portalauth>' . "\n" .
    					'</authentication>';
    			return trim(chop($resultstr));
    		}
    		 
    		function validatePortal ($portalData) {
    			$portAuth = array();
    			if(!strlen($portalData)) {
    				$portAuth[0] = false;
    				return $portAuth;
    			}
    			$xml = simplexml_load_string($portalData);
    			if(!$xml) {
    				$portAuth[0] = false;
    				return $portAuth;
    			}
    			$authenticated = $xml->portalauth->attributes()->{'authenticated'};
    			if($authenticated ==  "true") {
    				$portalid = $xml->portalauth->attributes()->{'portalId'};
    				(string) $portalRoles = $xml->portalauth->attributes()->{'portalRoles'};
    				if(strstr($portalRoles,'role_active_emp') || strstr($portalRoles,'role_sis_grad_active')) {
    					$portAuth[0] = true;
						// $portalid[0] == 'katcher' || 
						( $portalid[0] == 'katcher' || $portalid[0] == 'nboukas' || $portalid[0] == 'mschmid' || $portalid[0] == 'jlongo')  ? $portAuth[1] = (string) 'lime_sa' : $portAuth[1] = (string) $portalid[0];
						$portAuth[2] = null;
    				}
    				else {
					// Valid Login but user does not have the required permissions - Roles.
    					$portAuth[0] = false;
    					$portAuth[1] = (string) $portalid[0];
						$portAuth[2] = 'A';						
    				}
    			}
    			else {
					// Reverse authentication failed
    				$portAuth[0] = false;
					$portAuth[1] = 'Authentication failed';
					$portAuth[2] = 'B';
    			}
    			return ($portAuth);
    		}
    		$verify = Concordia_Send_To_Host ($token, $dbname, $lang = "ENG" );
    		$valid = validatePortal($verify);
    		if ($valid[0] == true)	{
    			$this->setUsername($valid[1]); 
				$this->setInvalidReason(null);
				// $this->setAuthPlugin(); // This plugin will handle authentication and skips the login form
    		} 
			else {
				$this->setUsername($valid[1]); 
				$this->setInvalidReason($valid[2]);		
			}
			$this->setAuthPlugin(); // This plugin will handle authentication and skips the login form			
    	} 
		else {
			$this->setInvalidReason('C');
		}
    }

    public function newUserSession() {
	//echo 'SHITTTTT';
	//die;
	
    	$sUser =  $this->getUserName();
    	$oUser =  $this->api->getUserByName($sUser);
    	$reason = $this->getInvalidReason();		
		if(!is_null($reason)) {
			if($reason == 'A') { 
				$this->setAuthFailure(555, strtoupper($sUser)." is not permitted to access this service.");
			}
			elseif ( $reason == 'B') { 
				$this->setAuthFailure(556, "Validation failure");
			}
			elseif ( $reason == 'C') { 
				$this->setAuthFailure(558, "Direct login forbidden");
			}
			else {
				$this->setAuthFailure(557, "Invalid Login Attempt");
			}			
			return;  
		}		
        if (!is_null($oUser)) {        	  	
           $this->setAuthSuccess($oUser);           
           return;
        }
    	else {    		
    		// Need to create new user';			
    		$SearchFor=$sUser;
    		$SearchField="cn";
    		$LDAPHost = "ldap://int-con-dc-3.concordia.ca";
    		$dn = "ou=People,dc=concordia,dc=ca";
    		$LDAPUser = "CN=iits_portal,ou=Roles,dc=concordia,dc=ca";
    		$LDAPUserPassword = "Esp=mc2";
    		$LDAPFieldsToFind = array("cn", "mail","givenName", "sn");
    		$cnx = ldap_connect($LDAPHost) or die("Could not connect to LDAP");
    		ldap_set_option($cnx, LDAP_OPT_PROTOCOL_VERSION, 3);
    		ldap_set_option($cnx, LDAP_OPT_REFERRALS, 0);
    		ldap_bind($cnx,$LDAPUser,$LDAPUserPassword) or die("Could not bind to LDAP");
    		error_reporting (E_ALL ^ E_NOTICE);
    		$filter="($SearchField=$SearchFor)";
    		$sr=ldap_search($cnx, $dn, $filter, $LDAPFieldsToFind);
    		$info = ldap_get_entries($cnx, $sr);    		 
    		if(!isset($info) or ($info['count'] == 0) ) {
    			$this->setAuthFailure(self::ERROR_PASSWORD_INVALID, "User not found in Active Directory");
    			return;
    		}
    		if(!isset($info[0]['mail'][0])) {
    			$this->setAuthFailure(self::ERROR_PASSWORD_INVALID, "A valid Email address is required");
				return;    			
    		}
    		
    		$oUser=new User;
    		$oUser->users_name=$sUser;
    		$oUser->password=hash('sha256', createPassword());
    		$oUser->full_name=$info[0]['givenname'][0] . ' '. $info[0]['sn'][0];
    		$oUser->parent_id=1;
    		$oUser->lang='en';
    		$oUser->email=$info[0]['mail'][0];
    		if ($oUser->save()) {
    			$permission=new Permission;
    			$permission->setPermissions($oUser->uid, 0, 'global', $this->api->getConfigKey('auth_webserver_autocreate_permissions'), true);
    			Permission::model()->setGlobalPermission($oUser->uid,'auth_db');
				// $this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));
    			$this->setAuthSuccess($oUser);
    			return;
    		}
    		else {
    			$this->setAuthFailure(self::ERROR_USERNAME_INVALID,"Unable to save new user");
    			return;
    		}
    	}
    }
	protected function setInvalidReason($invalidreason)
    {
        $this->_invalidreason = $invalidreason;

        return $this;
    }
	
	 /**
     * Get the reason for failure for necessary
     *
     * @return A | B | null
     */
    protected function getInvalidReason()
    {
        return $this->_invalidreason;
    }
}