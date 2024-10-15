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

    public function store(RegisterRequest $request){

    }

    private function convertToCreate(RegisterRequest $request) : User {
        return new User([

        ]);
    }
}
