<?php

class CurlUtil {
    public static function getWithCustomHeaders($url, $headers) {
        $handle = curl_init($url);

        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);

        $response = curl_exec($handle);
        curl_close($handle);

        return $response;
    }

    public static function postJsonData($url, $jsonData, $headers) {
        $handle = curl_init($url);

        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_POST, true);
        curl_setopt($handle, CURLOPT_POSTFIELDS, json_encode($jsonData));
        curl_setopt($handle, CURLOPT_HTTPHEADER, array_merge($headers, ['Content-Type: application/json']));

        $response = curl_exec($handle);
        curl_close($handle);

        return $response;
    }

    public static function deleteRequest($url, $headers) {
        $handle = curl_init($url);

        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'DELETE');
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);

        $response = curl_exec($handle);
        $httpCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        curl_close($handle);

        if ($httpCode == 200 || $httpCode == 204) {
            return true; // Deletion successful
        } else {
            return false; // Deletion failed
        }
    }

    public static function putFormData($url, $formData, $headers) {
        $handle = curl_init($url);

        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($handle, CURLOPT_POSTFIELDS, http_build_query($formData));
        curl_setopt($handle, CURLOPT_HTTPHEADER, array_merge($headers, ['Content-Type: application/x-www-form-urlencoded']));

        $response = curl_exec($handle);
        $httpCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        curl_close($handle);

        if ($httpCode == 200 || $httpCode == 204) {
            return true; // Update successful
        } else {
            return false; // Update failed
        }
    }

    public static function patchWithCustomUserAgent($url, $data, $userAgent, $headers) {
        $handle = curl_init($url);

        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'PATCH');
        curl_setopt($handle, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($handle, CURLOPT_HTTPHEADER, array_merge($headers, ['User-Agent: ' . $userAgent]));

        $response = curl_exec($handle);
        $httpCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        curl_close($handle);

        if ($httpCode == 200 || $httpCode == 204) {
            return true; // Update successful
        } else {
            return false; // Update failed
        }
    }

    public static function putJsonDataWithCustomHeaders($url, $jsonData, $headers) {
        $handle = curl_init($url);

        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($handle, CURLOPT_POSTFIELDS, json_encode($jsonData));
        curl_setopt($handle, CURLOPT_HTTPHEADER, array_merge($headers, ['Content-Type: application/json']));

        $response = curl_exec($handle);
        $httpCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        curl_close($handle);

        if ($httpCode == 200 || $httpCode == 204) {
            return true; // Update successful
        } else {
            return false; // Update failed
        }
    }
}

// Example usage for GET request
$url = 'https://enie5vdkc4eo.x.pipedream.net/data';
$headers = array(
    'X-Custom-Header: Value1',
    'Authorization: Bearer YourToken'
);

$response = CurlUtil::getWithCustomHeaders($url, $headers);
echo "GET Response: $response\n";

// Example usage for POST request
$postUrl = 'https://enie5vdkc4eo.x.pipedream.net/users';
$jsonData = array(
    'name' => 'John',
    'email' => 'john@example.com'
);

$postResponse = CurlUtil::postJsonData($postUrl, $jsonData, $headers);
echo "POST Response: $postResponse\n";

// Example usage for DELETE request
$deleteUrl = 'https://enie5vdkc4eo.x.pipedream.net/users/123';
$deleteResponse = CurlUtil::deleteRequest($deleteUrl, $headers);
if ($deleteResponse) {
    echo "DELETE Request: Deletion successful.\n";
} else {
    echo "DELETE Request: Deletion failed.\n";
}

// Example usage for PUT request
$putUrl = 'https://enie5vdkc4eo.x.pipedream.net/users/123';
$formData = array(
    'name' => 'Jane',
    'email' => 'jane@example.com'
);

$putResponse = CurlUtil::putFormData($putUrl, $formData, $headers);
if ($putResponse) {
    echo "PUT Request: Update successful.\n";
} else {
    echo "PUT Request: Update failed.\n";
}

// Example usage for PATCH request
$patchUrl = 'https://enie5vdkc4eo.x.pipedream.net/users/123';
$patchData = array(
    'status' => 'active'
);
$userAgent = 'MyCustomUserAgent/1.0';

$patchResponse = CurlUtil::patchWithCustomUserAgent($patchUrl, $patchData, $userAgent, $headers);
if ($patchResponse) {
    echo "PATCH Request: Update successful.\n";
} else {
    echo "PATCH Request: Update failed.\n";
}

// Example usage for PUT request with JSON data and custom headers
$putJsonUrl = 'https://enie5vdkc4eo.x.pipedream.net/settings/456';
$putJsonData = array(
    'theme' => 'dark',
    'notifications' => 'enabled'
);
$putJsonHeaders = array(
    'X-Request-ID: 789'
);

$putJsonResponse = CurlUtil::putJsonDataWithCustomHeaders($putJsonUrl, $putJsonData, array_merge($headers, $putJsonHeaders));
if ($putJsonResponse) {
    echo "PUT Request with JSON Data and Custom Headers: Update successful.\n";
} else {
    echo "PUT Request with JSON Data and Custom Headers: Update failed.\n";
}
?>
