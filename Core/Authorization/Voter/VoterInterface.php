<?php

namespace Ano\Bundle\SecurityBundle\Core\Authorization\Voter;

use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface as BaseVoterInterface;

interface VoterInterface extends BaseVoterInterface
{
    /**
     * @return string Uniquely identifies the voter
     */
    public function getName();
}