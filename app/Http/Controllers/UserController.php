<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Http\Requests\UserIdRequest;
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

    public function index() {
        $users = $this->service->index();

        if(count($users) == 0) return response(['error'=>'nenhum usuario encontrado'], 404);

        $resource = UserResource::collection($users);
        return $resource->response()->setStatusCode(200);
    }

    public function store (RegisterRequest $request){
        $user = $this->service->store($request);

        if(!$user) return response(['error'=>'Usuario nao criado'], 400);

        $resource = new UserResource($user);

        return $resource->response()->setStatusCode(201);
    }

    public function destroy (UserIdRequest $request){
        $userExist = $this->service->getById($request->id);

        if(!$userExist->id) return response(['error'=>'usuario nao existe'], 404);

        $userDeleted = $this->service->destroy($userExist->id);

        if(!$userDeleted) return response(['error'=>'usuario nao deletado'], 500);

        return response(['message'=>'usuario deletado com sucesso'], 200);
    }

}
