<?php

namespace Ano\Bundle\SecurityBundle\Security\Acl\Expression;

use JMS\SecurityExtraBundle\Security\Authorization\Expression\Ast\ConstantExpression;

use JMS\SecurityExtraBundle\Security\Authorization\Expression\Ast\VariableExpression;
use JMS\SecurityExtraBundle\Security\Authorization\Expression\Ast\FunctionExpression;
use JMS\SecurityExtraBundle\Security\Authorization\Expression\ExpressionCompiler;
use JMS\SecurityExtraBundle\Security\Authorization\Expression\Compiler\Func\FunctionCompilerInterface;

class IsGrantedFunctionCompiler implements FunctionCompilerInterface
{
    public function getName()
    {
        return 'isGranted';
    }

    public function compilePreconditions(ExpressionCompiler $compiler, FunctionExpression $function)
    {
        $compiler->verifyItem('token', 'Symfony\Component\Security\Core\Authentication\Token\TokenInterface');
    }

    public function compile(ExpressionCompiler $compiler, FunctionExpression $function)
    {
        $compiler
            ->compileInternal(new VariableExpression('security_context'))
            ->write('->isGranted(');


        if ($function->args[1] instanceof ConstantExpression) {
            $compiler->write(var_export(strtoupper($function->args[1]->value), true));
        } else {
            $compiler
                ->write('strtoupper(')
                ->compileInternal($function->args[1])
                ->write(')')
            ;
        }

        $compiler
            ->write(', ')
            ->compileInternal($function->args[0])
            ->write(')')
        ;
    }
}