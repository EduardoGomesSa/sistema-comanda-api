<?php

namespace App\Services;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserService {
    private User $user;

    function __construct(User $user)
    {
        $this->user = $user;
    }

    public function store(RegisterRequest $request) : User{
        $user = $this->user->create([
            'name'=> $request->name,
            'email'=>$request->email,
            'password'=> bcrypt($request->password),
        ]);

        $token = $user->createToken('auth-token')->plainTextToken;
        $user->token = $token;

        return $user;
    }

    public function login(LoginRequest $request) : User{
        $user = $this->user->where('name', $request->name)->first();

        if(!$user) return new User();

        if($user && Hash::check($request->password, $user->password)){
            $token = $user->createToken('auth-token')->plainTextToken;
            $user->token = $token;

            return $user;
        }

        return new User();
    }

    public function validateToken(Request $request) : User{
        if($token = $request->bearerToken()){
            $user = auth('sanctum')->user();
            $user->token = $token;

            return $user;
        }

        return new User();
    }

    private function convertToCreate(RegisterRequest $request) : User {
        return new User([

        ]);
    }
}
