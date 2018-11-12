<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
// use Request;
use Illuminate\Http\Request;
use App\User;
use DB;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    	/**
     * Create user account
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request){

        $user = new User([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => bcrypt($request->input('password')),
        ]);
        if ($user->save()) {
            return response()->json([
                'message' => 'user created successfully.',
                'user' => [
                    'href' => 'api/v1/login',
                    'method' => 'get',
                    'params' => 'email, password'
                ]
            ], 201);
        }
        return response()->json(['message'  => 'failed to create user']);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        // $credentials = request(['email', 'password']);

        // if (! $token = auth()->attempt($credentials)) {
        //     return response()->json(['error' => 'Unauthorized'], 401);
        // }

        // return $this->respondWithToken($token);

        $credentials = [
            'email' => $request->input('email'), 
            'password' => $request->input('password')
        ];
        // return response()->json(['user_id' => auth()->user()]);
        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        
        // $token = $this->respondWithToken($token);
        $email = $request->input('email');
        $nameUser = DB::table('users')->select('name')->where('email', '=', $email)->get();

        $user = Auth::user();
        return response()->json([
            'token' => $token,
            'status' => true,
            'dataUser'=>$user            
        ]);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}