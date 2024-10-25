<?php

namespace App\Http\Controllers;

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
}
