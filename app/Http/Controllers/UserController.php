<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Services\UserService;
use Illuminate\Http\Request;

class UserController extends Controller
{
    private UserService $service;

    public function __construct(UserService $service)
    {
        $this->service = $service;
    }

    public function store (RegisterRequest $request){
        $user = $this->service->store($request);

        if(!$user) return response(['error'=>'Usuario nao criado'], 400);

        $resource = new UserResource($user);

        return $resource->response()->setStatusCode(201);
    }

}
