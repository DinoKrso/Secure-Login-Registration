<?php
namespace Sssd;

use PDO;
use PDOException;
use OTPHP\TOTP;
use libphonenumber\PhoneNumberUtil;
use libphonenumber\NumberParseException;
use libphonenumber\PhoneNumberFormat;

class UserDao {
    private $db;

    public function __construct(PDO $db) {
        $this->db = $db;
    }

    public function registerUser($userData) {
        $fullName = $userData['full_name'];
        $username = $userData['username'];
        $email = $userData['email'];
        $password = $userData['password'];
        $phone = $userData['phone'];
        // Initialize the phone number util instance
        $phoneUtil = PhoneNumberUtil::getInstance();
        try {
            // Parse and validate the phone number
            $phoneNumber = $phoneUtil->parse($phone, null); // We can specify a default region if needed
            if (!$phoneUtil->isValidNumber($phoneNumber)) {
                echo "Invalid phone number.";
                return false;
            }
            // Format the phone number to E.164 standard
            $formattedPhone = $phoneUtil->format($phoneNumber, PhoneNumberFormat::E164);
    
        } catch (NumberParseException $e) {
            echo "Phone number validation failed: " . $e->getMessage();
            return false;
        }
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        // Generate OTP secret
        $otp = TOTP::create();
        $otpSecret = $otp->getSecret();
        $sql = "INSERT INTO Users (full_name, username, email, password, phone, otp_secret) 
                VALUES (:fullName, :username, :email, :password, :phone, :otpSecret)";
        try {
            // Prepare the SQL statement
            $stmt = $this->db->prepare($sql);
            // Bind parameters
            $stmt->bindParam(':fullName', $fullName);
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $hashedPassword); // Store the hashed password
            $stmt->bindParam(':phone', $formattedPhone);
            $stmt->bindParam(':otpSecret', $otpSecret);
            $stmt->execute();
            return true;
        } catch (PDOException $e) {
            // Handle database errors
            echo "Registration failed: " . $e->getMessage();
            return false;
        }
    }
public function loginUser($usernameOrEmail, $password) {    
    $sql = "SELECT idUsers, password, otp_secret FROM Users WHERE username = :usernameOrEmail OR email = :usernameOrEmail";
    try {
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':usernameOrEmail', $usernameOrEmail);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            // Verify the entered password against the hashed password
            if (password_verify($password, $user['password']) ) {
                return true ;
            }
            $totp = TOTP::CREATE($user['otp_secret']);
            if($totp->verify($password)){
                return true ;
            }
            echo 'Invalid password' ;
            return false ;
        }
        return false;
    } catch (PDOException $e) {
        echo "Login failed: " . $e->getMessage();
        return false;
    }
    }

    public function getOTPSecretForLoggedInUser($username) {
        $sql = "SELECT otp_secret FROM Users WHERE username = :username";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $otpSecret = $stmt->fetchColumn();
            return $otpSecret;
        } catch (PDOException $e) {
            echo "Failed to fetch OTP secret: " . $e->getMessage();
            return null;
        }
    }

    public function isEmailTaken($email){
        $sql = "SELECT COUNT(*) FROM Users WHERE email = :email";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $emailDB = $stmt->fetchColumn();
            return $emailDB>0;
    }

    public  function isUsernameTaken($username){
        $sql = "SELECT COUNT(*) FROM Users WHERE username = :username";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $usernameDB = $stmt->fetchColumn();
            return $usernameDB>0;
    }

    public function findUserByEmail($usernameOrEmail) {
        $sql = "SELECT * FROM Users WHERE username = :usernameOrEmail OR email = :usernameOrEmail" ;
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':usernameOrEmail', $usernameOrEmail);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ;
    }

    public function verifyUserEmail($email) {
        $sql = "UPDATE Users SET verified = 1 WHERE email = :email" ;
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':email', $email);
        return $stmt->execute();
    }

    public function checkEmailExists($email) {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM Users WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();
        $found = $stmt->fetchColumn() ;
        if ($found>0){
            return true ;
        }else{
            return false ; 
        }
    }

    public function updatePassword($email, $password) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->db->prepare("UPDATE Users SET password = :password WHERE email = :email");
        $stmt->bindParam(':password' , $hashedPassword) ; 
        $stmt->bindParam(':email' , $email) ; 
        return $stmt->execute();
    }

    public function isEmailVerified($email) {
        $stmt = $this->db->prepare("SELECT verified FROM Users WHERE email = :email");
        $stmt->bindParam(':email' , $email); 
        $stmt->execute();
        $result = $stmt->fetch();
        if ($result && $result['verified'] == 1) {
            return true;
        }
        return false;
    }
}
