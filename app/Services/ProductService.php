<?php

namespace App\Services;

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

    public function create(ProductRequest $request){
        $productExist = $this->product->where('name', $request['name'])->first();

        if($productExist) return null;

        $productCreated = $this->product->create($request->all());

        if(!$productCreated) return null;

        $resource = new ProductResource($productCreated);

        return $resource;
    }
}
