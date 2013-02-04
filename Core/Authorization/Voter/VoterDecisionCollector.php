<?php

namespace Ano\Bundle\SecurityBundle\Core\Authorization\Voter;

class VoterDecisionCollector
{
    /** @var array */
    private $decisions;

    public function __construct()
    {
        $this->decisions = array();
    }

    public function addDecision(VoterInterface $voter, $context, $decision)
    {
        if (!$this->hasDecisionsForVoter($voter->getName())) {
            $this->decisions[$voter->getName()] = array();
        }

        $this->decisions[$voter->getName()] = array(
            'context' => $context,
            'decision' => $decision,
        );
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function hasDecisionsForVoter($name)
    {
        return isset($this->decisions[$name]);
    }

    /**
     * @return bool
     */
    public function hasDecisions()
    {
        return !empty($this->decisions);
    }

    /**
     * @return array
     */
    public function getDecisions()
    {
        return $this->decisions;
    }
}