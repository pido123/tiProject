<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Http\Request;

class GoogleAuthController extends Controller
{
    public function redirectToGoogle()
    {
        $clientId = config('services.google.client_id');
        $redirectUri = config('services.google.redirect');
        $response_type = 'code';
        $scope = 'profile email';

        return redirect()->away("https://accounts.google.com/o/oauth2/auth?client_id={$clientId}&redirect_uri={$redirectUri}&response_type={$response_type}&scope={$scope}");
    }

    public function handleGoogleCallback(Request $request)
    {
        $userData = null;

        $clientId = config('services.google.client_id');
        $clientSecret = config('services.google.client_secret');
        $redirectUri = config('services.google.redirect');
        $code = $request->query('code');
        $grant_type = 'authorization_code';

        //gets access token from google
        $accessToken = $this->getAccessToken($clientId, $clientSecret, $redirectUri, $code, $grant_type);

        if ($accessToken) {
            $userData = $this->getUserData($accessToken);
        } else {
            return response()->json(['error' => 'Unable to retrieve access token from Google'], 400);
        }

        //checks if user already exists in database
        $user = User::where('email', $userData['email'])->first();

        if (!$user) {
            $user = $this->createUserInDatabase($userData['name'], $userData['email']);
        }

        //authenticates the user and gets an authentication token
        $token = $this->authenticateUser($user);

        //redirects to dashboard
        return redirect('/dashboard')->with(['access_token' => $token]);
    }

    private function getAccessToken($clientId, $clientSecret, $redirectUri, $code, $grant_type)
    {
        $response = Http::asForm()->post('https://oauth2.googleapis.com/token', [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'grant_type' => $grant_type
        ]);

        $accessToken = json_decode((string) $response->getBody(), true)['access_token'];
        return $accessToken;
    }

    private function getUserData($accessToken)
    {
        return Http::withHeaders([
            'Authorization' => "Bearer {$accessToken}",
            'Accept' => 'application/json',
        ])->get('https://www.googleapis.com/oauth2/v1/userinfo');
    }

    private function authenticateUser($user)
    {
        //ceates a new token for user
        $token = $user->createToken('Google Token')->accessToken;

        //log in user
        Auth::login($user);

        return $token;
    }

    private function createUserInDatabase($name, $email)
    {
        $user = new User();
        $user->name = $name;
        $user->email = $email;
        // Sets a random password
        $user->password = bcrypt(Str::random(32));
        $user->save();

        return $user;
    }
}
