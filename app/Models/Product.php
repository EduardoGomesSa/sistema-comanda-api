<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'description',
        'price',
        'status',
    ];

    public function getStatusAttribute($value){
        return $value === 0 ? 'disponivel' : 'indisponivel';
    }

    public function setStatusAttribute($value){
        $this->attributes['status'] = $value === 'disponivel' ? 0 : 1;
    }
}
