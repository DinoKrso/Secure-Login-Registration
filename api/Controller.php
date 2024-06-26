<?php


namespace Sssd;

use Config as GlobalConfig;
use OTPHP\TOTP;
require_once '../config_default.php' ;
require '../vendor/autoload.php'; 
use libphonenumber\PhoneNumberUtil;
use OpenApi\Annotations as OA;  
use Flight as Flight;
use PDO ;
use PDOException;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;
use PSpell\Config;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Controller {
    private $userDao;
    private $jwtSecret ;

    public function __construct(PDO $db) {
        $this->userDao = new UserDao($db);
    }

/**
* @OA\Post(
*     path="/register",
*     summary="Register User",
*     description="Register a new user",
*     tags={"Users"},
*     @OA\RequestBody(
*         required=true,
*         description="Provide user details for registration",
*         @OA\JsonContent(
*             required={"full_name", "username", "email", "password", "phone"},
*             @OA\Property(property="full_name", type="string", format="text", example="John Doe"),
*             @OA\Property(property="username", type="string", format="text", example="johndoe"),
*             @OA\Property(property="email", type="string", format="email", example="johndoe@example.com"),
*             @OA\Property(property="password", type="string", format="text", example="password123"),
*             @OA\Property(property="phone", type="string", format="text", example="1234567890"),
*         ),
*     ),
*     @OA\Response(
*         response=200,
*         description="User successfully registered",
*         @OA\JsonContent(
*             @OA\Property(property="error", type="boolean", example="false"),
*             @OA\Property(property="message", type="string", example="User successfully registered"),
*         )
*     ),
*     @OA\Response(
*         response=500,
*         description="Failed to register user",
*         @OA\JsonContent(
*             @OA\Property(property="error", type="boolean", example="true"),
*             @OA\Property(property="message", type="string", example="Failed to register user"),
*         )
*     )
* )
*/
   public function register($userData) {
  // Get the request body
       $request_body = Flight::request()->getBody();

        // Decode the JSON data
       $userData = json_decode($request_body, true);

        // Check if decoding was successful and $userData is an array
        if (is_array($userData)) {
            // Call UserDao to register the user
            return $this->userDao->registerUser($userData);
        } else {
            // JSON decoding failed or $userData is not an array
            return false;
        }
}


    
/**
* @OA\Post(
*     path="/login",
*     summary="Login User",
*     description="Authenticate user",
*     tags={"Users"},
*     @OA\RequestBody(
*         required=true,
*         description="Provide login credentials",
*         @OA\JsonContent(
*             required={"email", "password"},
*             @OA\Property(property="email", type="string", format="email", example="johndoe@example.com"),
*             @OA\Property(property="password", type="string", format="text", example="password123"),
*         ),
*     ),
*     @OA\Response(
*         response=200,
*         description="Login successful",
*         @OA\JsonContent(
*             @OA\Property(property="error", type="boolean", example="false"),
*             @OA\Property(property="message", type="string", example="Login successful"),
*         )
*     ),
*     @OA\Response(
*         response=401,
*         description="Unauthorized - Invalid credentials",
*         @OA\JsonContent(
*             @OA\Property(property="error", type="boolean", example="true"),
*             @OA\Property(property="message", type="string", example="Unauthorized - Invalid credentials"),
*         )
*     )
* )
*/
public function login($loginData) {

    // Login data from user input
    $usernameOrEmail = $loginData['username'];
    $password = $loginData['password'];

    // Verify hCaptcha
    if(isset($loginData['h-captcha-response'])) {
        $data = array(
            'secret' => HCAPTCHA_SERVER_SECRET,
            'response' => $loginData['h-captcha-response']
        );
        $verify = curl_init();
        curl_setopt($verify, CURLOPT_URL, "https://hcaptcha.com/siteverify");
        curl_setopt($verify, CURLOPT_POST, true);
        curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($verify);
        $responseData = json_decode($response);
        if (!$responseData->success) {
            // hCaptcha verification failed
            Flight::json(["error" => "hCaptcha verification failed. Please try again."]);
            return;
        }
    } else {
        // hCaptcha response not set
        Flight::json(["error" => "hCaptcha response not set."]);
        return;
    }

    // Call UserDao function to authenticate user
    $userId = $this->userDao->loginUser($usernameOrEmail, $password);

    if ($userId) {
        // User is authenticated
        Flight::json(["message" => "Login successful"]);
        return true ;
    } else {
        // Invalid credentials
        Flight::json(["error" => "Invalid credentials. Please try again."]);
        return false ;
    }
}

public function verifyJWT() {
    $authHeader = Flight::request()->getHeader('Authorization');
    if ($authHeader) {
        $arr = explode(" ", $authHeader);
        $jwt = $arr[1];

        if ($jwt) {
            try {
                $decoded = JWT::decode($jwt, new Key($this->jwtSecret, 'HS256'));
                return (array)$decoded->data;
            } catch (\Exception $e) {
                Flight::json(['error' => 'Unauthorized'], 401);
                return false;
            }
        }
    }

    Flight::json(['error' => 'Token not provided'], 401);
    return false;
}
/**
* @OA\Get(
*     path="/user-data",
*     summary="Get User Data",
*     description="Returns user data for authenticated user",
*     tags={"Users"},
*     @OA\Response(
*         response=200,
*         description="User data retrieved successfully",
*         @OA\JsonContent(
*             @OA\Property(property="data", type="object", description="User data")
*         )
*     ),
*     @OA\Response(
*         response=401,
*         description="Unauthorized",
*         @OA\JsonContent(
*             @OA\Property(property="error", type="string", example="Unauthorized")
*         )
*     )
* )
*/

public function getUserData() {
    $userData = $this->verifyJWT();
    if ($userData) {
        Flight::json(['data' => $userData]);
    }
}


/**
 * Check if a password is compromised using the Have I Been Pwned Passwords API.
 *
 * @param string $password The password to check.
 * @return bool True if the password is compromised, false otherwise.
 *
 * @OA\Post(
 *     path="/check-password",
 *     summary="Check if a password is compromised",
 *     description="Checks if a password is compromised using the Have I Been Pwned Passwords API.",
 *     tags={"Password Security"},
 *     @OA\RequestBody(
 *         required=true,
 *         description="Password to be checked",
 *         @OA\JsonContent(
 *             required={"password"},
 *             @OA\Property(property="password", type="string", format="password", example="password123")
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="Success response",
 *         @OA\JsonContent(
 *             @OA\Property(property="compromised", type="boolean", example="true", description="Indicates whether the password is compromised")
 *         )
 *     ),
 *     @OA\Response(
 *         response=400,
 *         description="Error response",
 *         @OA\JsonContent(
 *             @OA\Property(property="error", type="string", example="Could not retrieve data from the API.", description="Error message")
 *         )
 *     )
 * )
 */
public function checkPassword($password) {
    // Hash the password
    $sha1Password = strtoupper(sha1($password));
    $prefix = substr($sha1Password, 0, 5);
    $suffix = substr($sha1Password, 5);

    // Make the API request
    $ch = curl_init("https://api.pwnedpasswords.com/range/" . $prefix);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);

    if ($response === false) {
        // Handle error
        exit('Could not retrieve data from the API.');
    }

    // Search the response
    if (strpos($response, $suffix) !== false) {
        return true; // Password found in breach corpus
    } else {
        return false; // Password not found
    }
}
/**
 * @OA\Get(
 *     path="/generate-qr-code",
 *     summary="Generate QR code for a user",
 *     tags={"QR Code"},
 *     @OA\Parameter(
 *         name="username",
 *         in="query",
 *         description="Username of the user",
 *         required=true,
 *         @OA\Schema(
 *             type="string"
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="QR code generated successfully",
 *         @OA\JsonContent(
 *             type="object",
 *             @OA\Property(
 *                 property="qr_code_uri",
 *                 type="string",
 *                 description="URL of the generated QR code image"
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=400,
 *         description="Bad request - Username is required",
 *         @OA\JsonContent(
 *             type="object",
 *             @OA\Property(
 *                 property="error",
 *                 type="string",
 *                 description="Error message"
 *             )
 *         )
 *     )
 * )
 */
public function generateQRCodeForUser($username) {
    // Get the OTP secret for the specified username from the database
    $otpSecret = $this->userDao->getOTPSecretForLoggedInUser($username);

    // Generate QR code for the OTP secret
    $otp = TOTP::createFromSecret($otpSecret);
    $otp->setLabel($username);
    $grCodeUri = $otp->getQrCodeUri('https://api.qrserver.com/v1/create-qr-code/?data='.$otpSecret.'&size=300x300&ecc=M', $otpSecret);
    // Return the QR code
   return $grCodeUri ;
}

public function validateEmailDomain($email) {
    $parts = explode('@', $email);
    $domain = $parts[1];
    
    // Validate TLD
    $validTLDs = file('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $domainParts = explode('.', $domain);
    $tld = end($domainParts);

    if (!in_array(strtoupper($tld), $validTLDs)) {
        return false;
    }

    // Validate MX record
    $mxRecords = [];
    if (getmxrr($domain, $mxRecords)) {
        return true;
    } else {
        return false;
    }
}
/**
 * @OA\Post(
 *     path="/validate-email-domain",
 *     summary="Validate Email Domain",
 *     tags={"Validation"},
 *     @OA\RequestBody(
 *         required=true,
 *         description="Email to be validated",
 *         @OA\JsonContent(
 *             required={"email"},
 *             @OA\Property(property="email", type="string", format="email", example="johndoe@example.com")
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="Email domain is valid",
 *         @OA\JsonContent(
 *             @OA\Property(property="valid", type="boolean", example="true")
 *         )
 *     ),
 *     @OA\Response(
 *         response=400,
 *         description="Email domain is invalid",
 *         @OA\JsonContent(
 *             @OA\Property(property="valid", type="boolean", example="false")
 *         )
 *     )
 * )
 */
function isValidPhoneNumber($phoneNumber, $regionCode = "BA") {
    $phoneNumberUtil = PhoneNumberUtil::getInstance();
    try {
        $parsedNumber = $phoneNumberUtil->parse($phoneNumber, $regionCode);
        return $phoneNumberUtil->isValidNumber($parsedNumber);
    } catch (\libphonenumber\NumberParseException $e) {
        return false;
    }
}
/**
 * @OA\Post(
 *     path="/validate-phone-number",
 *     summary="Validate Phone Number",
 *     tags={"Validation"},
 *     @OA\RequestBody(
 *         required=true,
 *         description="Phone number to be validated",
 *         @OA\JsonContent(
 *             required={"phoneNumber"},
 *             @OA\Property(property="phoneNumber", type="string", format="text", example="1234567890")
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="Phone number is valid",
 *         @OA\JsonContent(
 *             @OA\Property(property="valid", type="boolean", example="true")
 *         )
 *     ),
 *     @OA\Response(
 *         response=400,
 *         description="Phone number is invalid",
 *         @OA\JsonContent(
 *             @OA\Property(property="valid", type="boolean", example="false")
 *         )
 *     )
 * )
 */

function sendRegistrationEmail($userData) {
    //Logic for for not hard coding localhost
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'];
    $script = $_SERVER['SCRIPT_NAME'];
    $basePath = str_replace(basename($script), '', $script);
    $baseUrl = $protocol . $host . $basePath;

    $request_body = Flight::request()->getBody();
    $userData = json_decode($request_body, true);
    try {
        // Initialize PHPMailer
        $mail = new PHPMailer(true);

        // Enable debugging, currently set to 0 so it doesnt shows bugs.
        $mail->SMTPDebug = 0;

        // SMTP configuration
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = SMTP_ENCRYPTION;
        $mail->Port = SMTP_PORT;

        // Sender information
        $mail->setFrom('from@example.com', 'SSSD Login');

        // Recipient information
        $mail->addAddress($userData['email'], $userData['full_name']);

        // Email content
        $mail->isHTML(true);
        $mail->Subject = 'Welcome to our platform';
        $verificationLink = $baseUrl . 'validate?email=' . urlencode($userData['email']);
        $mail->Body = 'Dear ' . $userData['full_name'] . ',<br>Welcome to our platform!<br><br>Please click the button below to verify your email address:<br><br><a href="' . $verificationLink . '" style="background-color: #4CAF50; color: white; padding: 15px 32px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer; border-radius: 8px;">Verify Email</a>';
        $mail->AltBody = 'Dear ' . $userData['full_name'] . ', Welcome to our platform! Please visit the following link to verify your email address: ' . $verificationLink;

        // Send email
        if (!$mail->send()) {
            // Log error and return false
            error_log('Error sending registration email: ' . $mail->ErrorInfo);
            return false;
        } else {
            // Email sent successfully
            return true;
        }
    } catch (Exception $e) {
        // Log exception and return false
        error_log('Exception sending registration email: ' . $e->getMessage());
        return false;
    }
}
/**
 * @OA\Post(
 *     path="/send-registration-email",
 *     summary="Send Registration Email",
 *     tags={"Email"},
 *     @OA\RequestBody(
 *         required=true,
 *         description="User data for sending email",
 *         @OA\JsonContent(
 *             required={"full_name", "email"},
 *             @OA\Property(property="full_name", type="string", example="John Doe"),
 *             @OA\Property(property="email", type="string", format="email", example="johndoe@example.com")
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="Email sent successfully",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Email sent successfully")
 *         )
 *     ),
 *     @OA\Response(
 *         response=500,
 *         description="Failed to send email",
 *         @OA\JsonContent(
 *             @OA\Property(property="error", type="string", example="Failed to send email")
 *         )
 *     )
 * )
 */
function sendRecoveryEmail($email) {
    //Logic for for not hard coding localhost
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'];
    $script = $_SERVER['SCRIPT_NAME'];
    $basePath = str_replace(basename($script), '', $script);
    $baseUrl = $protocol . $host . $basePath;

    $request_body = Flight::request()->getBody();
    $email = json_decode($request_body, true);
    try {
        // Initialize PHPMailer
        $mail = new PHPMailer(true);

        $mail->SMTPDebug = 0;

        // SMTP configuration
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = SMTP_ENCRYPTION;
        $mail->Port = SMTP_PORT;

        // Sender information
        $mail->setFrom('from@example.com', 'SSSD Login');

        // Recipient information
        $mail->addAddress($email['email']);

        // Email content
        $mail->isHTML(true);
        $mail->Subject = 'Password Reset Link';
        $verificationLink = $baseUrl . 'changepassword?email=' . urlencode($email['email']);
        $mail->Body = 'Dear User,<br><br>You have requested to reset your password.<br><br>Please click the button below to set up a new password:<br><br><a href="' . $verificationLink . '" style="background-color: #4CAF50; color: white; padding: 15px 32px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer; border-radius: 8px;">Set Up New Password</a>';
        $mail->AltBody = 'Dear User, You have requested to reset your password. Please visit the following link to set up a new password: ' . $verificationLink;
        
        // Send email
        if (!$mail->send()) {
            // Log error and return false
            error_log('Error sending password reset email: ' . $mail->ErrorInfo);
            return false;
        } else {
            // Email sent successfully
            return true;
        }
    } catch (Exception $e) {
        // Log exception and return false
        error_log('Exception sending password reset email: ' . $e->getMessage());
        return false;
    }
}
// checking if mail is taken
function checkMail($email){
    $check = $this->userDao->isEmailTaken($email) ;
    return $check;
}
// checking if username is taken
function checkUsername($username){
    $check = $this->userDao->isUsernameTaken($username) ;
    return $check;
}

function findUser($loginData){
    return $this->userDao->findUserByEmail($loginData['username']) ;
}

//This function is used by Verfiying Email Adress Logic
function verifyEmail(){
    $email = Flight::request()->query['email']  ;
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        Flight::json(['status' => 'error', 'message' => 'Invalid email address'], 400);
        return;
    }
    $isVerified = $this->userDao->findUserByEmail($email) ;
    if ($isVerified) {
        $this->userDao->verifyUserEmail($email);
        Flight::json(['status' => 'success', 'message' => 'Email verified successfully']);
        return true ;
    } else {
        Flight::json(['status' => 'error', 'message' => 'Email verification failed'], 400);
        return  false ;
    }
}
//This function is used by Password Reset Logic
public function findEmail($email) {
    $found = $this->userDao->checkEmailExists($email);
    $isVerified = $this->userDao->isEmailVerified($email);
    if($found) {
        // Logic for sending verification email can be added here
        if($isVerified){
        $this->sendRecoveryEmail($email) ;
        Flight::json(['status' => 'success', 'message' => 'Email Verification sent']);
        }else{
            Flight::json(['status' => 'error', 'message' => 'Email must be verified']);

        }
    } else {
        Flight::json(['status' => 'error', 'message' => 'Email not found']);
    }
}
// function for changing user password
public function changePassword($email, $password) {
    if ($this->userDao->updatePassword($email, $password)) {
        // Password updated successfully
        Flight::json(['message' => 'Password updated successfully']);
    } else {
        // Failed to update password (e.g., email not found)
        Flight::json(['message' => 'Failed to update password']);
    }
}

public function sendSMS($phone, $message) {
    $curl = curl_init();

    $data = array(
        'messages' => array(
            array(
                'destinations' => array(
                    array(
                        'to' => $phone
                    )
                ),
                'from' => 'SSSD Login',
                'text' => $message
            )
        )
    );

    $payload = json_encode($data);

    curl_setopt_array($curl, array(
        CURLOPT_URL => API_URL_SMS ,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => 'POST',
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => array(
            'Authorization: App ' . API_KEY_SMS,
            'Content-Type: application/json',
            'Accept: application/json'
        ),
    ));

    $response = curl_exec($curl);

    curl_close($curl);
    return $response;
}

}
