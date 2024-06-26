<?php
require '../vendor/autoload.php';
require '../dao/UserDao.php';
require_once '../config_default.php';
use Sssd\Controller;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
// Initialize database connection
$dbHost = DB_HOST;
$dbName = DB_NAME;
$dbUser = DB_USERNAME;
$dbPass = DB_PASSWORD;

try {
    $db = new PDO("mysql:host=$dbHost;dbname=$dbName", $dbUser, $dbPass);
    // Set PDO to throw exceptions on errors
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    // Handle connection errors
    echo "Connection failed: " . $e->getMessage();
    exit();
}
$controller = new Controller($db);


// Define a route that handles requests to the root URL
Flight::route('/', function () {
    require '../index.html';
});
Flight::route('/check-connection', function () use ($db) {
    try {
        $result = $db->query('SELECT 1');
        if ($result) {
            echo "Database connection is active!";
        } else {
            echo "Unable to execute query. Database connection may be down.";
        }
    } catch (PDOException $e) {
        // Handle query execution errors
        echo "Error executing query: " . $e->getMessage();
    }
});
$controller = new Controller($db);
Flight::route('POST /register', function () use ($controller) {
    $userData = Flight::request()->data->getData();
    // Extract information from user data
    $password = $userData['password'];
    $email = $userData['email'] ;
    $username= $userData['username'];
    $phone = $userData['phone'];
    // Check if the password is pawned
    if ($controller->checkPassword($password)) {
        Flight::json(['error' => 'Password is compromised. Choose a different password.'], 400);
        return;
    }

    // Validate phone number
    if (!$controller->isValidPhoneNumber($userData['phone'])) {
        Flight::json(['error' => 'Invalid phone number'], 400);
        return;
    }

    // Validate email
    if (!$controller->validateEmailDomain($userData['email'])) {
        Flight::json(['error' => 'Invalid email address'], 400);
        return;
    }
    //validate if username is taken 
    if($controller->checkUsername($username)){
        Flight::json(['error' => 'Username is already taken'], 400);
        return;
    }
     //validate if mail is taken 
    if($controller->checkMail($email)){
        Flight::json(['error' => 'Email is already taken'], 400);
        return;
    }
    // Register User
    $result = $controller->register($userData);
    // Handle the result
    if ($result && !isset($result['error'])) {
        Flight::json(['message' => 'User registered successfully'], 200);
        $controller->sendRegistrationEmail($userData);
        $controller->sendSMS($phone,'Welcome to our app');
    } else {
        // Check if the result is an array and contains an error message
        if (is_array($result) && isset($result['error'])) {
            Flight::json(['error' => $result['error']], 500);
        } else {
            Flight::json(['error' => 'Failed to register user'], 500);
        }
    }
});

 Flight::route('POST /login', function () use ($controller) {
    $jwtSecret = JWT_SECRET ;
    $decodedJwtSecret = base64_decode($jwtSecret); //
    $loginData = Flight::request()->data->getData();
    $user = $controller->findUser($loginData) ;
    $login = $controller->login($loginData);
   
        if (isset($user['idUsers'] )) {
           if ($login){
            $expiration_time =  time() + 3600 ;
            $payload =[ 
                'idUsers' => $user['idUsers'],
                'full_name' => $user['full_name'],
                'username' => $user['username'],
                'email' => $user['email'],
                'phone' => $user['phone'],
                'verified' => $user['verified'],
                'exp' => $expiration_time
                ];
            $jwt = JWT::encode($payload, $decodedJwtSecret, 'HS256');
            Flight::response()->header('Authorization', 'Bearer ' . $jwt);
            // User is authenticated
            Flight::json(['token' => $jwt]);        }
            } else {
            // Invalid credentials, redirect back to login page with an error message
            Flight::json(["error"=>"login failed"]);
        }    

});
Flight::route('GET /register', function () {
    // Load the HTML registration form
    require '../registration_form.html';
});
Flight::route('GET /login', function () {
    // Load the HTML login form
    require '../login_form.html';
});
Flight::route('GET /home', function () {
    // Load the HTML login form
    require '../homepage.html';
    //$this->$controller->verifyJWT() ;

});
Flight::route('GET /recover', function () {
    // Load the HTML login form
    require '../password_recover.html';
});
Flight::route('GET /validate', function () {
    // Load the HTML login form
    require '../emailVerified.html';
});
Flight::route('GET /changepassword', function () {
    // Load the HTML login form
    require '../password_change.html';
});
Flight::route('GET /generate-qr-code', function () use ($controller) {
    // Retrieve the username from the request query parameters
    $username = Flight::request()->query['username'] ?? null;

    if (!$username) {
        // Username is required, return an error response
        Flight::json(['error' => 'Username is required'], 400);
        return;
    }

    // Generate QR code for the specified username
    $qrCodeUri = $controller->generateQRCodeForUser($username);

    // Return the QR code URI to the user
    Flight::redirect($qrCodeUri);
});

Flight::route('GET /users', function ($controller) {
    $loginData = Flight::request()->data->getData();
    $user = $controller->findUser($loginData) ;
    Flight::json(["Data" => $user]) ;

 });
 Flight::route('POST /validate', function() use ($controller){
    $verify = $controller->verifyEmail() ;
    if(!$verify){
        Flight::json(['message' => 'User verified failed']); 
    }

 });
 Flight::route('POST /verifyemail', function() use ($controller){
    $data = Flight::request()->data->getData();
    if (isset($data['email'])) {
       $controller->findEmail($data['email']);
    } else {
        Flight::json(['message' => 'Invalid request']);
    }

 });
 Flight::route('POST /changepassword', function() use ($controller){
    $email = Flight::request()->query['email'];
    $password = Flight::request()->data->password;
    if ($email && $password) {
        $controller->changePassword(urldecode($email), $password);
    } else {
        Flight::json(['message' => 'Invalid request']);
    }
});
Flight::start();