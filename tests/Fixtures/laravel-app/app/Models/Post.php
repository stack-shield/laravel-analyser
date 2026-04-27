<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    // No $fillable or $guarded - vulnerable to mass assignment
}
