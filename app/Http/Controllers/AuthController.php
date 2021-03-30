<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Encryption\Encrypter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Storage;
use Seffeng\LaravelRSA\Facades\RSA;
use Seffeng\LaravelRSA\Exceptions\RSAException;

class AuthController extends Controller
{
    private $cryptRSA;
    private $publicKey;
    private $privateKey;
//    private $sign;

    /**
     * AuthController constructor.
     * @param $cryptRSA
     * @param $publicKey
     * @param $privateKey
     */
    public function __construct(RSA $cryptRSA)
    {
        $this->cryptRSA = $cryptRSA;
        $this->publicKey = file_get_contents(storage_path('rsa-public.key'));
        $this->privateKey = file_get_contents(storage_path('rsa-private.key'));
    }


    public function signUp(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);

        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        $user->save();

        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;

        return response()->json([
            'message' => 'done',
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer'
        ], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        $credentials = request(['email', 'password']);
        if(!Auth::attempt($credentials))
            return response()->json([
                'message' => __('auth.login_failed')
            ], 401);

        $user = $request->user();

        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;

        $token->save();
        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
        ]);
    }

    public function user(Request $request)
    {
        return response()->json($request->user());
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json('done');
    }

    public function sendData(Request $request)
    {
//        $entext = $this->cryptRSA::encrypt($request->boo);
//        $message = 'a=aaa&b=bbb&c=ccc';
//        $sign = $this->sign($request->boo);
//        return response()->json(base64_encode($entext));
        try {
            $plaintext = $request->boo;
            // 加密
            $entext = RSA::encrypt($plaintext);
            // 解密
//            $detext = RSA::decrypt($entext);
//            $message = $this->publicKey;

//            $this->sign = RSA::sign($message);
//            $verify = RSA::verify($message, $sign);
            return response()->json([
                base64_encode($entext)]);

        } catch (RSAException $e) {
            var_dump($e->getMessage());
        } catch (\Exception $e) {
            var_dump($e->getMessage());
        }
    }

    public function receiveData(Request $request)
    {
        try {
            $detext = $this->cryptRSA::decrypt(base64_decode($request->boo));
        return response()->json(json_decode($detext));

        } catch (RSAException $e) {
            var_dump($e->getMessage());
        } catch (\Exception $e) {
            var_dump($e->getMessage());
        }
        return response()->json([], 404);
    }

}
