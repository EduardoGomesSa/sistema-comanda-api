<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Services\UserService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    private $user;
    private $service;

    public function __construct(User $user, UserService $service)
    {
        $this->user = $user;
        $this->service = $service;
    }

    public function register(RegisterRequest $request){
        $user = $this->service->store($request);

        if(!$user) return response(['error'=>'Usuario nao foi criado'], 400);

        $resource = new UserResource($user);

        return $resource->response()->setStatusCode(201);
    }

    public function login(LoginRequest $request){
        $user = $this->service->login($request);

        if(!$user->id)return response(['error'=>'Usuario ou senha estao incorretos'], 400);

        $resource = new UserResource($user);

        return $resource->response()->setStatusCode(200);
    }

    public function validateToken(Request $request){
        $user = $this->service->validateToken($request);

        if(!$user->id) return response(['error'=>'Usuario não está logado'], 400);

        return new UserResource($user);
    }
}
