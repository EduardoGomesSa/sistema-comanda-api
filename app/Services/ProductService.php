<?php

namespace App\Services;

use App\Http\Requests\ProductChangeStatusRequest;
use App\Http\Requests\ProductRequest;
use App\Http\Resources\ProductResource;
use App\Models\Product;

class ProductService {
    private Product $product;

    public function __construct(Product $product) {
        $this->product = $product;
    }

    public function getAll() {
        return ProductResource::collection(
            $this->product->get()
        );
    }

    public function getById($id) {
        $product = $this->product->find($id);

        if(!$product) return null;

        return $product;
    }

    public function create(ProductRequest $request){
        $productExist = $this->product->where('name', $request['name'])->first();

        if($productExist) return null;

        $productCreated = $this->product->create($request->all());

        if(!$productCreated) return null;

        $resource = new ProductResource($productCreated);

        return $resource;
    }

    public function update() {

    }

    public function changeStatus(ProductChangeStatusRequest $request) : bool{
        $productExist = $this->getById($request['id']);

        if(!$productExist) return false;

        $productUpdated = $productExist->update($request->all());

        if($productUpdated > 0) return true;

        return false;
    }
}
