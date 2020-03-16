<?php

namespace SeuAppAqui\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;
use SeuAppAqui\Socialite\Providers\AppleSocialiteProvider;
use SocialiteProviders\Manager\Exception\MissingConfigException;

class AppleServiceProvider extends ServiceProvider
{
  public function register()
  {
    $this->mergeConfigFrom(__DIR__ . "../config/services.php", 'services');
  }

  public function boot()
  {
    $socialite = $this->app->make(Factory::class);

    $socialite->extend(
      'apple',
      function ($app) use ($socialite) {
        $config = $app['config']['apple'];

        if (!$config) throw new MissingConfigException("Not found apple configuration in services.php file.");

        foreach ($config as $key => $value) {
          if (!$value) throw new MissingConfigException("Not found value in apple.{$key} on services.php file.");
        }

        return $socialite->buildProvider(AppleSocialiteProvider::class, $config);
      }
    );
  }
}
