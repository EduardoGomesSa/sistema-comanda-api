<?php

namespace App\Services;

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
}
