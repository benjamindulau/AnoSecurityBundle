<?php

namespace Ano\Bundle\SecurityBundle\Http\Authorization;

use Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Bundle\FrameworkBundle\Templating\EngineInterface;
use Ano\Bundle\SecurityBundle\Core\Authorization\Voter\VoterDecisionCollector;

class DefaultAccessDeniedHandler implements AccessDeniedHandlerInterface
{
    private $decisionCollector;
    private $templating;

    public function __construct(VoterDecisionCollector $decisionCollector, EngineInterface $templating)
    {
        $this->decisionCollector = $decisionCollector;
        $this->templating = $templating;
    }

    public function handle(Request $request, AccessDeniedException $accessDeniedException)
    {
        $response = $this->templating->renderResponse('AnoSecurityBundle::access_denied.html.twig', array(
            'decision_collector' => $this->decisionCollector,
        ));
        $response->setStatusCode(403);

        return $response;
    }
}