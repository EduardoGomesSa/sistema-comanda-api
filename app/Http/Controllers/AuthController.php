<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use phpDocumentor\Reflection\Types\Resource_;

class AuthController extends Controller
{
    private $user;

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    public function register(RegisterRequest $request){
        $user = $this->user->create([
            'name'=> $request->name,
            'email'=>$request->email,
            'password'=> bcrypt($request->password),
        ]);

        $token = $user->createToken('auth-token')->plainTextToken;
        $user->token = $token;

        $resource = new UserResource($user);
        return $resource->response()->setStatusCode(201);
    }

    public function login(LoginRequest $request){
        $user = $this->user->where('email', $request->email)->first();

        if(!$user) {
            return response(['error'=>'O email informado nao esta cadastrado'], 404);
        }

        if($user && Hash::check($request->password, $user->password)){
            $token = $user->createToken('auth-token')->plainTextToken;
            $user->token = $token;

            return new UserResource($user);
        }

        return response(['error'=>'A senha informada esta esta incorreta'], 401);
    }

    public function validateToken(Request $request){
        if($token = $request->bearerToken()){
            $user = auth('sanctum')->user();
            $user->token = $token;
            return new UserResource($user);
        }
    }
}
