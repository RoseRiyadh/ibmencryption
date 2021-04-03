<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\EncryptionController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('/login', [AuthController::class, 'login']);
Route::post('/signup', [AuthController::class, 'signUp']);
// AES
Route::post('/en-a', [EncryptionController::class, 'encryptDataByAES']);
Route::post('/de-a', [EncryptionController::class, 'decryptDataByAES']);
// RSA
Route::post('/en-r', [EncryptionController::class, 'encryptDataByRSA']);
Route::post('/de-r', [EncryptionController::class, 'decryptDataByRSA']);
// AES + RSA
Route::post('/en-ra', [EncryptionController::class, 'encryptDataByAESRSA']);
Route::post('/de-ra', [EncryptionController::class, 'decryptDataByAESRSA']);
Route::get('/user', [AuthController::class, 'user']);
Route::get('/logout', [AuthController::class, 'logout']);

Route::get('/hello', [EncryptionController::class, 'hello']);
