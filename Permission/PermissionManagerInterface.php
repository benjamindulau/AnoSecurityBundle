<?php

/**
 * This file is part of the AnoSecurityBundle
 *
 * (c) anonymation <contact@anonymation.com>
 *
 */

namespace Ano\Bundle\SecurityBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;

/**
 * Abstraction of Symfony2's ACLs/ACEs common operations
 *
 * @author Benjamin Dulau <benjamin.dulau@anonymation.com>
 */
interface PermissionManagerInterface
{
    const ON_OBJECT = 1;
    const ON_CLASS = 2;

    const TO_USER = 10;
    const TO_ROLE = 11;

    const FROM_USER = 20;
    const FROM_ROLE = 21;

    /**
     * @param array $privileges
     * @param int   $onType
     * @param mixed $onValue
     * @param int   $toType
     * @param mixed $toValue
     *
     * @return mixed
     */
    public function grantPrivileges(array $privileges, $onType, $onValue, $toType, $toValue);

    /**
     * @param array $privileges
     * @param int   $onType
     * @param mixed $onValue
     * @param int   $fromType
     * @param mixed $fromValue
     *
     * @return mixed
     */
    public function revokePrivileges(array $privileges, $onType, $onValue, $fromType, $fromValue);
}