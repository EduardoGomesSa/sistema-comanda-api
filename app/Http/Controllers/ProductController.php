<?php

namespace App\Http\Controllers;

use App\Http\Requests\ProductChangeStatusRequest;
use App\Http\Requests\ProductRequest;
use App\Http\Requests\ProductUpdateRequest;
use App\Services\ProductService;
use Illuminate\Http\Request;

class ProductController extends Controller
{
    private ProductService $service;

    public function __construct(ProductService $service) {
        $this->service = $service;
    }

    public function index() {
        $products = $this->service->getAll();

        if(count($products) == 0) return response(['message'=>'nenhum produto encontrado'], 404);

        return $products->response()->setStatusCode(200);
    }

    public function store(ProductRequest $request){
        $productCreated = $this->service->create($request);

        if(!$productCreated) return response(['error' => 'produto nao foi criado'], 400);

        return $productCreated->response()->setStatusCode(400);
    }

    public function update(ProductUpdateRequest $request){
        $productUpdated = $this->service->update($request);

        if(!$productUpdated) return response(['error' => 'produto nao atualizado'], 400);

        return response(['message' => 'produto atualizado com sucesso'], 201);
    }

    public function changeStatus(ProductChangeStatusRequest $request){
        $productUpdated = $this->service->changeStatus($request);

        if(!$productUpdated) return response(['error' => 'produto nao atualizado'], 400);

        return response(['message' => 'produto atualizado com sucesso'], 201);
    }
}
