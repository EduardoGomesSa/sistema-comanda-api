<?php

namespace App\Http\Controllers;

use App\Http\Requests\ProductRequest;
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
}
