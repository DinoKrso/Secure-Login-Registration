<?php

class TextMessages {
    private $api_url;
    private $api_key;

    public function __construct($api_url, $api_key) {
        $this->api_url = $api_url;
        $this->api_key = $api_key;
    }

    public function sendSMS($mobile_number, $message) {
        $curl = curl_init();

        $data = array(
            'messages' => array(
                array(
                    'destinations' => array(
                        array(
                            'to' => $mobile_number
                        )
                    ),
                    'from' => 'InfoSMS',
                    'text' => $message
                )
            )
        );

        $payload = json_encode($data);

        curl_setopt_array($curl, array(
            CURLOPT_URL => $this->api_url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => array(
                'Authorization: App ' . $this->api_key,
                'Content-Type: application/json',
                'Accept: application/json'
            ),
        ));

        $response = curl_exec($curl);

        curl_close($curl);
        return $response;
    }
}
$api_url = 'https://2v3xew.api.infobip.com/sms/2/text/advanced';
$api_key = '4a68747b7eb15a51405c54200792732d-9127fb81-878e-4a25-b48b-4980128c2c65';

$textMessages = new TextMessages($api_url, $api_key);
$response = $textMessages->sendSMS('387603400423', 'Update version of message');
echo $response;

?>
