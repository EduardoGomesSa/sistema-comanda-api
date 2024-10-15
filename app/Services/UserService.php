<?php

namespace App\Services;

use App\Http\Requests\RegisterRequest;
use App\Models\User;

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

    private function convertToCreate(RegisterRequest $request) : User {
        return new User([

        ]);
    }
}
