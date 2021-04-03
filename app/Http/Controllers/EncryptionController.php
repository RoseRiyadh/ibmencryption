<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Seffeng\LaravelRSA\Facades\RSA;

class EncryptionController extends Controller
{
    private $message = '&oytzaohbtrejvkf%#sj&*uapwk^rs%*qn!&b!&v!&orsdexc!qrjkzrb#%wu*xwi';
    private $publicKey;
    /**
     * [OPENSSL_ALGO_SHA1, OPENSSL_ALGO_MD5, OPENSSL_ALGO_MD4, OPENSSL_ALGO_SHA224, OPENSSL_ALGO_SHA256, OPENSSL_ALGO_SHA384, OPENSSL_ALGO_SHA512, OPENSSL_ALGO_RMD160]
     * @var integer
     */
    protected $signatureMode = OPENSSL_ALGO_SHA1;
    /**
     * EncryptionController constructor.
     */
    public function __construct()
    {
        $this->publicKey = file_get_contents(storage_path('rsa-public.key'));
    }


    /**
     * encrypt data with AES
     * return base 64 encoded data
     * catch exception if found
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function encryptDataByAES(Request $request)
    {
        $data = $request->validate([
            'data' => 'required'
        ]);
        try
        {
            $encrypted = encrypt($data['data']);
            return response()->json(base64_encode($encrypted));
        } catch (\Exception $e) {
            return response()->json(['message' => $e->getMessage()], 400);
        }
    }

    /**
     * decode data from base 64
     * decrypt data from AES encryption
     * return json decoded data
     * catch exception if found
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function decryptDataByAES(Request $request)
    {
        $data = $request->validate([
            'data' => 'required'
        ]);
        try
        {
            $decrypted = decrypt(base64_decode($data['data']));
            return response()->json(base64_encode($decrypted));
        } catch (\Exception $e) {
            return response()->json(['message' => $e->getMessage()], 400);
        }
    }

    /**
     * encrypt data with RSA
     * return base 64 encoded data
     * catch exception if found
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function encryptDataByRSA(Request $request)
    {
        $data = $request->validate([
            'data' => 'required'
        ]);
        try {
            $encrypted = RSA::encrypt($data['data']);
            return response()->json(base64_encode($encrypted));
        } catch (\Exception $e) {
            return response()->json(['message' => $e->getMessage()], 400);
        }
    }

    /**
     * decode data from base 64
     * decrypt data from RSA encryption
     * return json decoded data
     * catch exception if found
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function decryptDataByRSA(Request $request)
    {
        $data = $request->validate([
            'data' => 'required'
        ]);
        try {
            $decrypted = RSA::decrypt((base64_decode($data['data'])));

            return response()->json(json_decode($decrypted));
        } catch (\Exception $e) {
            return response()->json(['message' => $e->getMessage()], 400);
        }
    }

    /**
     * encrypt data with AES encryption
     * encrypt AES Key with RSA encryption
     * by decrypting the key will give credentials to the sign phase
     * sign RSA with a given random message
     * return the encrypted data, with encryptedKey and signature with being encoded to base 64
     * catch exception if found
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function encryptDataByAESRSA(Request $request)
    {
        $data = $request->validate([
            'data' => 'required'
        ]);
        try {
            $aes = encrypt($data['data']);
            $encrypted = RSA::encrypt(ENV('APP_KEY'));
            $d = RSA::decrypt($encrypted);
            $sign = RSA::sign($this->message);
            return response()->json([
                'data' => base64_encode($aes), // data
                'encryptedKey' => base64_encode($encrypted), // encrypted
                'signature' => base64_encode($sign) // sign
            ]);
        } catch (\Exception $e) {
            return response()->json(['message' => $e->getMessage()], 400);
        }
    }

    /**
     * decode signature of base 64
     * verify signature by the main function in the RSA package (Inherited by cryptlib package)
     * decode encryptedKey  of base 64
     * decrypt encryptedKey from RSA encryption
     * check if the encryptedKey is the same as the key of the API
     * decode data  of base 64
     * decrypt data from AES encryption
     * catch exception if found
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function decryptDataByAESRSA(Request $request)
    {
        $data = $request->validate([
            'data' => 'required',
            'encryptedKey' => 'required',
            'signature' => 'required'
        ]);
        try {
            $verify = openssl_verify($this->message, base64_decode($data['signature']), $this->publicKey, $this->signatureMode);
            if ($verify == 1)
            {
                $encryptedKey = base64_decode($data['encryptedKey']);
                $decrypted = RSA::decrypt($encryptedKey);
                if ($decrypted == ENV('APP_KEY'))
                {
                    $aesEncrypted = base64_decode($data['data']);
                    $aesDecrypted = decrypt($aesEncrypted);
                    return response()->json(['data' => $aesDecrypted]);
                }
            }
            return response()->json(['message' => 'not decrypted.'], 400);
        } catch (\Exception $e) {
            return response()->json(['message' => $e->getMessage()], 400);
        }
    }
}
