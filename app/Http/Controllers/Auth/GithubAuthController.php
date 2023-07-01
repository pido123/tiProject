<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Http\Request;

class GithubAuthController extends Controller
{
    public function redirectToGithub()
    {
        $clientId = config('services.github.client_id');
        $redirectUri = config('services.github.redirect');
        $scope = 'user:email';

        return redirect()->away("https://github.com/login/oauth/authorize?client_id={$clientId}&redirect_uri={$redirectUri}&scope={$scope}");
    }

    public function handleGithubCallback(Request $request)
    {
        $clientId = config('services.github.client_id');
        $clientSecret = config('services.github.client_secret');
        $redirectUri = config('services.github.redirect');
        $code = $request->query('code');

        $accessToken = $this->getAccessToken($clientId, $clientSecret, $redirectUri, $code);

        if ($accessToken) {
            $userData = $this->getUserData($accessToken);
        } else {
            return response()->json(['error' => 'Unable to retrieve access token from GitHub'], 400);
        }

        //checks if user already exists in database
        $user = User::where('email', $userData['email'])->first();

        if (!$user) {
            $user = $this->createUserInDatabase($userData['username'], $userData['email']);
        }

        //authenticates the user and gets an authentication token
        $token = $this->authenticateUser($user);

        //redirects to dashboard
        return redirect('/dashboard')->with(['access_token' => $token]);
    }

    private function getAccessToken($clientId, $clientSecret, $redirectUri, $code)
    {
        $response = Http::asForm()->post('https://github.com/login/oauth/access_token', [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'code' => $code,
            'redirect_uri' => $redirectUri,
        ]);

        $responseData = Str::of($response->body())
            ->after('access_token=')
            ->before('&scope=');

        return $responseData;
    }

    private function getUserData($accessToken)
    {
        //getting user data
        $userData = Http::withHeaders([
            'Authorization' => "Bearer {$accessToken}",
            'Accept' => 'application/json',
        ])->get('https://api.github.com/user');

        //filtering out the username
        $username = $userData->json()['login'];

        //getting emails data
        $emails = Http::withHeaders([
            'Authorization' => "Bearer {$accessToken}",
            'Accept' => 'application/json',
        ])->get('https://api.github.com/user/emails');

        //filtering out primary email
        $primaryEmail = null;

        foreach ($emails->json() as $email) {
            if ($email['primary']) {
                $primaryEmail = $email['email'];
                break;
            }
        }

        //return as array
        return [
            'username' => $username,
            'email' => $primaryEmail
        ];
    }

    private function authenticateUser($user)
    {
        //ceates a new token for user
        $token = $user->createToken('Google Token')->accessToken;

        //log in user
        Auth::login($user);

        return $token;
    }

    private function createUserInDatabase($username, $email)
    {
        $user = new User();
        $user->name = $username;
        $user->email = $email;
        // Sets a random password
        $user->password = bcrypt(Str::random(32));
        $user->save();

        return $user;
    }
}
